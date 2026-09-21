package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tianacloud/sdk-go/internal/localfile"
)

const instanceTokensFileName = "instance-tokens.json"

// InstanceTokenCredential is one delivered InstanceToken. It is keyed by MGR
// origin, Tenant, instance, and Token so a new Token never overwrites another
// Token's credential.
type InstanceTokenCredential struct {
	Origin     string    `json:"origin"`
	TenantID   string    `json:"tenant_id"`
	InstanceID string    `json:"instance_id"`
	TokenID    string    `json:"token_id"`
	Name       string    `json:"name,omitempty"`
	Token      string    `json:"token"`
	ExpiresAt  int64     `json:"expires_at"`
	EndpointID string    `json:"endpoint_id,omitempty"`
	SavedAt    time.Time `json:"saved_at"`
}

// InstanceTokenStore persists a delivered InstanceToken and reports a
// human-readable location for the delivery message.
type InstanceTokenStore interface {
	Save(InstanceTokenCredential) (string, error)
	Lookup(instanceID, endpointID string, now time.Time) (InstanceTokenCredential, error)
}

var ErrInstanceTokenNotFound = errors.New("no usable local InstanceToken")

// Lookup must only follow successful instance resolution under the current
// account. MGR authorizes instance access; existing records are scoped by origin,
// tenant, globally unique instance ID and endpoint, not by the Token creator.
// No network validation, mutation, automatic token creation or fallback retry.
func (s *FileInstanceTokenStore) Lookup(instanceID, endpointID string, now time.Time) (InstanceTokenCredential, error) {
	if s == nil || s.Origin == "" || instanceID == "" || endpointID == "" {
		return InstanceTokenCredential{}, ErrInstanceTokenNotFound
	}
	data, err := localfile.Read(s.Path, 8*1024*1024, true)
	if errors.Is(err, os.ErrNotExist) {
		return InstanceTokenCredential{}, ErrInstanceTokenNotFound
	}
	if err != nil {
		return InstanceTokenCredential{}, errors.New("cannot read local InstanceTokens: require an owned, regular mode-0600 file, no symlinks, at most 8 MiB")
	}
	defer clear(data)
	var file instanceTokenFile
	if json.Unmarshal(data, &file) != nil {
		return InstanceTokenCredential{}, errors.New("invalid local InstanceToken store")
	}
	var best InstanceTokenCredential
	tenant := ""
	for key, candidate := range file.Tokens {
		if canonicalOriginKey(candidate.Origin) != s.Origin || candidate.InstanceID != instanceID || candidate.EndpointID != endpointID {
			continue
		}
		want, keyErr := instanceTokenStorageKey(s.Origin, candidate)
		if keyErr != nil || key != want {
			return InstanceTokenCredential{}, errors.New("inconsistent local InstanceToken identity")
		}
		if tenant != "" && tenant != candidate.TenantID {
			return InstanceTokenCredential{}, errors.New("ambiguous local InstanceToken tenant")
		}
		tenant = candidate.TenantID
		if candidate.ExpiresAt != InstanceTokenNoExpiry && candidate.ExpiresAt <= now.Add(30*time.Second).Unix() {
			continue
		}
		if best.TokenID == "" || candidate.SavedAt.After(best.SavedAt) || (candidate.SavedAt.Equal(best.SavedAt) && candidate.TokenID > best.TokenID) {
			best = candidate
		}
	}
	if best.TokenID == "" {
		return best, ErrInstanceTokenNotFound
	}
	return best, nil
}

// FileInstanceTokenStore reads and writes the CLI-compatible token file.
// Writers serialize across processes; Lookup requires prior MGR authorization.
type FileInstanceTokenStore struct {
	Path   string
	Origin string
}

// NewFileInstanceTokenStore builds a local file store for InstanceTokens.
func NewFileInstanceTokenStore(path, origin string) *FileInstanceTokenStore {
	return &FileInstanceTokenStore{Path: path, Origin: canonicalOriginKey(origin)}
}

func (s *FileInstanceTokenStore) Save(credential InstanceTokenCredential) (string, error) {
	if s == nil || s.Path == "" || s.Origin == "" {
		return "", errors.New("InstanceToken store is not configured")
	}
	if credential.Origin == "" {
		credential.Origin = s.Origin
	}
	if credential.SavedAt.IsZero() {
		credential.SavedAt = time.Now().UTC()
	}
	key, err := instanceTokenStorageKey(s.Origin, credential)
	if err != nil {
		return "", err
	}
	unlock, err := lockStore(context.Background(), s.Path)
	if err != nil {
		return "", err
	}
	defer unlock()
	file := instanceTokenFile{Tokens: map[string]InstanceTokenCredential{}}
	if contents, readErr := readPrivateStore(s.Path); readErr == nil {
		defer clear(contents)
		if err := json.Unmarshal(contents, &file); err != nil {
			return "", errors.New("InstanceToken store is invalid")
		}
		if file.Tokens == nil {
			file.Tokens = map[string]InstanceTokenCredential{}
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", fmt.Errorf("read InstanceToken store: %w", readErr)
	}
	file.Tokens[key] = credential
	contents, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return "", errors.New("encode InstanceToken store")
	}
	if err := atomicWritePrivate(s.Path, contents); err != nil {
		return "", err
	}
	return s.Path, nil
}

type instanceTokenFile struct {
	Tokens map[string]InstanceTokenCredential `json:"tokens"`
}

// NewInstanceTokenStore stores InstanceTokens in the private local configuration directory.
func NewInstanceTokenStore(origin string) (InstanceTokenStore, error) {
	origin = canonicalOriginKey(origin)
	if origin == "" {
		return nil, errors.New("MGR origin is required")
	}
	path, err := DefaultInstanceTokenPath()
	if err != nil {
		return nil, err
	}
	return NewFileInstanceTokenStore(path, origin), nil
}

func instanceTokenStorageKey(origin string, credential InstanceTokenCredential) (string, error) {
	origin = canonicalOriginKey(origin)
	if origin == "" || credential.TenantID == "" || credential.InstanceID == "" || credential.TokenID == "" {
		return "", errors.New("InstanceToken credential is incomplete")
	}
	if credential.Token == "" {
		return "", errors.New("InstanceToken credential has no secret")
	}
	return strings.Join([]string{origin, credential.TenantID, credential.InstanceID, credential.TokenID}, "|"), nil
}

func DefaultInstanceTokenPath() (string, error) {
	directory, err := credentialDirectory()
	if err != nil {
		return "", errors.New("resolve InstanceToken directory")
	}
	return filepath.Join(directory, instanceTokensFileName), nil
}

// InstanceTokenNoExpiry is the Unix-second sentinel for unlimited lifetime.
const InstanceTokenNoExpiry int64 = -1
