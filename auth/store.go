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

var (
	ErrCredentialNotFound = errors.New("credential not found")
)

const (
	credentialsFileName = "credentials.json"
	maxCredentialBytes  = 8 * 1024 * 1024
	lockWaitTimeout     = 30 * time.Second
)

// CredentialStore persists one CLI credential. Implementations must never
// include the raw credential in an error string.
type CredentialStore interface {
	Load() (Credential, error)
	Save(Credential) error
	Delete() error
}

// FileStore persists credentials locally. Its JSON object is keyed by the
// MGR origin so changing environments cannot reuse another environment's
// credential.
type FileStore struct {
	Path   string
	Origin string
}

func NewFileStore(path, origin string) *FileStore {
	return &FileStore{Path: path, Origin: canonicalOriginKey(origin)}
}

func (s *FileStore) Load() (Credential, error) {
	if s == nil || s.Path == "" || s.Origin == "" {
		return Credential{}, ErrCredentialNotFound
	}
	contents, err := readPrivateStore(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, ErrCredentialNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("read credential store: %w", err)
	}
	defer clear(contents)
	var file credentialFile
	if err := json.Unmarshal(contents, &file); err != nil {
		return Credential{}, errors.New("credential store is invalid")
	}
	credential, ok := file.Credentials[s.Origin]
	if !ok || credential.AccessToken == "" || credential.RefreshToken == "" {
		return Credential{}, ErrCredentialNotFound
	}
	return credential, nil
}

func (s *FileStore) Save(credential Credential) error {
	return s.withLock(context.Background(), func(store CredentialStore) error { return store.Save(credential) })
}

func (s *FileStore) save(credential Credential) error {
	if s == nil || s.Path == "" || s.Origin == "" {
		return errors.New("credential store is not configured")
	}
	if credential.AccessToken == "" || credential.RefreshToken == "" {
		return errors.New("credential is incomplete")
	}
	file := credentialFile{Credentials: map[string]Credential{}}
	if contents, err := readPrivateStore(s.Path); err == nil {
		defer clear(contents)
		if err := json.Unmarshal(contents, &file); err != nil {
			return errors.New("credential store is invalid")
		}
		if file.Credentials == nil {
			file.Credentials = map[string]Credential{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read credential store: %w", err)
	}
	file.Credentials[s.Origin] = credential
	contents, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return errors.New("encode credential store")
	}
	return atomicWritePrivate(s.Path, contents)
}

func (s *FileStore) Delete() error {
	if s == nil || s.Path == "" || s.Origin == "" {
		return nil
	}
	return s.withLock(context.Background(), func(store CredentialStore) error { return store.Delete() })
}

func (s *FileStore) delete() error {
	if s == nil || s.Path == "" || s.Origin == "" {
		return nil
	}
	contents, err := readPrivateStore(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read credential store: %w", err)
	}
	defer clear(contents)
	var file credentialFile
	if err := json.Unmarshal(contents, &file); err != nil {
		return errors.New("credential store is invalid")
	}
	if _, ok := file.Credentials[s.Origin]; !ok {
		return nil
	}
	delete(file.Credentials, s.Origin)
	if len(file.Credentials) == 0 {
		if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove credential store: %w", err)
		}
		return nil
	}
	updated, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return errors.New("encode credential store")
	}
	return atomicWritePrivate(s.Path, updated)
}

type credentialFile struct {
	Credentials map[string]Credential `json:"credentials"`
}

func NewCredentialStore(origin string) (CredentialStore, error) {
	origin = canonicalOriginKey(origin)
	if origin == "" {
		return nil, errors.New("MGR origin is required")
	}
	path, err := DefaultCredentialPath()
	if err != nil {
		return nil, err
	}
	return NewFileStore(path, origin), nil
}

func DefaultCredentialPath() (string, error) {
	directory, err := credentialDirectory()
	if err != nil {
		return "", errors.New("resolve credential directory")
	}
	return filepath.Join(directory, credentialsFileName), nil
}

// credentialDirectory uses the same local configuration path on every platform.
func credentialDirectory() (string, error) {
	if directory := os.Getenv("XDG_CONFIG_HOME"); directory != "" {
		return filepath.Join(directory, "tiana"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "tiana"), nil
}

func atomicWritePrivate(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if len(contents) > maxCredentialBytes {
		return errors.New("credential store exceeds 8 MiB")
	}
	if err := localfile.PrivateDir(directory); err != nil {
		return err
	}
	temporary, err := localfile.CreateTemp(directory, ".tiana-credentials-*")
	if err != nil {
		return fmt.Errorf("create private credential file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set private credential permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write private credential file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync private credential file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close private credential file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace private credential file: %w", err)
	}
	return nil // Replacement retains the private permissions established before writing.
}

func canonicalOriginKey(origin string) string {
	return strings.TrimRight(strings.TrimSpace(origin), "/")
}

func DefaultOrigin() string {
	return strings.TrimSpace(os.Getenv("TIANA_API_ORIGIN"))
}

// readPrivateStore preserves NotExist but deliberately omits arbitrary path/OS
// details from diagnostics. It validates the opened inode, not a prior stat.
func readPrivateStore(path string) ([]byte, error) {
	contents, err := localfile.Read(path, maxCredentialBytes, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, errors.New("credential store requires an owned regular mode-0600 file, no symlinks, at most 8 MiB")
	}
	return contents, nil
}

func lockStore(ctx context.Context, path string) (func(), error) {
	ctx, cancel := context.WithTimeout(ctx, lockWaitTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := localfile.PrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return localfile.Lock(ctx, path+".lock")
}

// lockedFileStore is deliberately unexported: it may be used only while the
// matching persistent file lock is held. This avoids nested Save/Delete locks.
type lockedFileStore struct{ store *FileStore }

func (s lockedFileStore) Load() (Credential, error) { return s.store.Load() }
func (s lockedFileStore) Save(c Credential) error   { return s.store.save(c) }
func (s lockedFileStore) Delete() error             { return s.store.delete() }
func (s *FileStore) withLock(ctx context.Context, fn func(CredentialStore) error) error {
	if s == nil || s.Path == "" || s.Origin == "" {
		return errors.New("credential store is not configured")
	}
	unlock, err := lockStore(ctx, s.Path)
	if err != nil {
		return err
	}
	defer unlock()
	return fn(lockedFileStore{s})
}
