//go:build windows

package localfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")")
}

func ownedDescriptor(handle windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return nil, errors.New("local file must belong to the current user")
	}
	return sd, nil
}

func checkPrivate(handle windows.Handle) error {
	sd, err := ownedDescriptor(handle)
	if err != nil {
		return err
	}
	owner, _, _ := sd.Owner()
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return errors.New("local file requires a private ACL")
	}
	var allowed windows.ACCESS_MASK
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(owner) {
			return errors.New("local file requires an owner-only ACL")
		}
		allowed |= ace.Mask
	}
	// Read and write are required, as with the existing exact mode-0600 policy.
	if allowed&windows.FILE_GENERIC_READ != windows.FILE_GENERIC_READ || allowed&windows.FILE_GENERIC_WRITE != windows.FILE_GENERIC_WRITE {
		return errors.New("local file requires owner read and write access")
	}
	return nil
}

func fileInfo(handle windows.Handle, noFollow bool) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		return info, errors.New("local input must be a disk file")
	}
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || (noFollow && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0) {
		return info, errors.New("local input must be a regular file")
	}
	return info, nil
}

// Read validates the opened handle and does not follow a final reparse point.
// Private input must have the Windows equivalent of owned mode-0600 access.
func Read(path string, limit int64, private bool) ([]byte, error) {
	return read(path, limit, private, true)
}

func read(path string, limit int64, private, noFollow bool) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if noFollow {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), path)
	defer f.Close()
	info, err := fileInfo(handle, noFollow)
	if err != nil {
		return nil, err
	}
	if uint64(info.FileSizeHigh)<<32|uint64(info.FileSizeLow) > uint64(limit) {
		return nil, errors.New("local file exceeds limit")
	}
	if private {
		if err := checkPrivate(handle); err != nil {
			return nil, err
		}
	}
	contents, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(contents)) > limit {
		clear(contents)
		return nil, errors.New("cannot read bounded local file")
	}
	return contents, nil
}

// PrivateDir checks the opened directory's owner and rejects reparse points.
// MAXIMUM_ALLOWED prevents SetSecurityInfo from propagating ACL changes to
// existing children; directory preparation must not change a stored file's ACL.
func PrivateDir(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New("cannot create private directory parent")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sd, err := privateDescriptor()
	if err != nil {
		return err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, &attrs); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return errors.New("cannot create private directory")
	}
	handle, err := windows.CreateFile(name, windows.MAXIMUM_ALLOWED, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errors.New("cannot open private directory")
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("unsafe private directory")
	}
	if _, err := ownedDescriptor(handle); err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// CreateTemp creates the private ACL together with the file, before any content
// is written. Windows chmod does not restrict access to other users.
func CreateTemp(directory, pattern string) (*os.File, error) {
	sd, err := privateDescriptor()
	if err != nil {
		return nil, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for range 10 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		suffix := hex.EncodeToString(random[:])
		name := pattern + suffix
		if i := strings.LastIndexByte(pattern, '*'); i >= 0 {
			name = pattern[:i] + suffix + pattern[i+1:]
		}
		path := filepath.Join(directory, name)
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(handle), path), nil
	}
	return nil, errors.New("cannot create unique private file")
}
