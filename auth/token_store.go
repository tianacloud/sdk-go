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
// origin, Tenant, and Token so a new Token never overwrites another
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
	CandidateIDs(tenantID string, now time.Time) ([]string, error)
	LookupCandidates(tenantID string, tokenIDs []string, now time.Time) (InstanceTokenCredential, error)
}

var ErrInstanceTokenNotFound = errors.New("no usable local InstanceToken")

// CandidateIDs returns only locally usable identifiers. MGR remains the source
// of truth for whether any identifier applies to a requested endpoint.
func (s *FileInstanceTokenStore) CandidateIDs(tenantID string, now time.Time) ([]string, error) {
	file, err := s.readTokens()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(file.Tokens))
	for key, candidate := range file.Tokens {
		if candidate.TenantID != tenantID || canonicalOriginKey(candidate.Origin) != s.Origin || !usableCandidate(candidate, now) {
			continue
		}
		want, keyErr := instanceTokenStorageKey(s.Origin, candidate)
		if keyErr != nil || key != want {
			return nil, errors.New("inconsistent local InstanceToken identity")
		}
		ids = append(ids, candidate.TokenID)
	}
	return ids, nil
}

// LookupCandidates selects only from IDs authorized by MGR. It never falls
// back to another local secret.
func (s *FileInstanceTokenStore) LookupCandidates(tenantID string, tokenIDs []string, now time.Time) (InstanceTokenCredential, error) {
	allowed := make(map[string]struct{}, len(tokenIDs))
	for _, id := range tokenIDs {
		allowed[id] = struct{}{}
	}
	file, err := s.readTokens()
	if err != nil {
		return InstanceTokenCredential{}, err
	}
	var best InstanceTokenCredential
	for key, candidate := range file.Tokens {
		if _, ok := allowed[candidate.TokenID]; !ok || candidate.TenantID != tenantID || canonicalOriginKey(candidate.Origin) != s.Origin || !usableCandidate(candidate, now) {
			continue
		}
		want, keyErr := instanceTokenStorageKey(s.Origin, candidate)
		if keyErr != nil || key != want {
			return InstanceTokenCredential{}, errors.New("inconsistent local InstanceToken identity")
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

func usableCandidate(candidate InstanceTokenCredential, now time.Time) bool {
	return candidate.ExpiresAt == InstanceTokenNoExpiry || candidate.ExpiresAt > now.Add(30*time.Second).Unix()
}

func (s *FileInstanceTokenStore) readTokens() (instanceTokenFile, error) {
	if s == nil || s.Origin == "" {
		return instanceTokenFile{}, ErrInstanceTokenNotFound
	}
	data, err := localfile.Read(s.Path, 8*1024*1024, true)
	if errors.Is(err, os.ErrNotExist) {
		return instanceTokenFile{Tokens: map[string]InstanceTokenCredential{}}, nil
	}
	if err != nil {
		return instanceTokenFile{}, errors.New("cannot read local InstanceTokens: require an owned, regular mode-0600 file, no symlinks, at most 8 MiB")
	}
	defer clear(data)
	var file instanceTokenFile
	if json.Unmarshal(data, &file) != nil {
		return instanceTokenFile{}, errors.New("invalid local InstanceToken store")
	}
	if file.Tokens == nil {
		file.Tokens = map[string]InstanceTokenCredential{}
	}
	return file, nil
}

// FileInstanceTokenStore reads and writes the CLI-compatible token file.
// Writers serialize across processes; LookupCandidates requires prior MGR authorization.
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

// UnmarshalJSON accepts the timestamp format written by pre-SDK CLI versions.
// Keep this compatibility at the file boundary; API expiry remains Unix seconds.
func (f *instanceTokenFile) UnmarshalJSON(data []byte) error {
	type credentialFields InstanceTokenCredential
	var stored struct {
		Tokens map[string]struct {
			credentialFields
			Expiry json.RawMessage `json:"expires_at"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return errors.New("invalid InstanceToken file")
	}
	tokens := make(map[string]InstanceTokenCredential, len(stored.Tokens))
	for key, record := range stored.Tokens {
		credential := InstanceTokenCredential(record.credentialFields)
		var seconds int64
		if len(record.Expiry) != 0 && json.Unmarshal(record.Expiry, &seconds) != nil {
			var timestamp string
			if json.Unmarshal(record.Expiry, &timestamp) != nil {
				return errors.New("invalid InstanceToken expiry")
			}
			if timestamp == "9999-12-31T23:59:59.999Z" {
				seconds = InstanceTokenNoExpiry
			} else {
				expiry, err := time.Parse(time.RFC3339Nano, timestamp)
				if err != nil || expiry.Unix() < 0 {
					return errors.New("invalid InstanceToken expiry")
				}
				// Round down, never extending an old token's lifetime. In particular,
				// a pre-epoch timestamp must not become the -1 no-expiry sentinel.
				seconds = expiry.Unix()
			}
		}
		credential.ExpiresAt = seconds
		tokens[key] = credential
	}
	f.Tokens = tokens
	return nil
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
	if origin == "" || credential.TenantID == "" || credential.TokenID == "" {
		return "", errors.New("InstanceToken credential is incomplete")
	}
	if credential.Token == "" {
		return "", errors.New("InstanceToken credential has no secret")
	}
	return strings.Join([]string{origin, credential.TenantID, credential.TokenID}, "|"), nil
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
