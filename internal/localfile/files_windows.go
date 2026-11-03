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

	"golang.org/x/sys/windows"
)

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
func Read(path string, limit int64, _ bool) ([]byte, error) {
	return read(path, limit, true)
}

func read(path string, limit int64, noFollow bool) ([]byte, error) {
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
	contents, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(contents)) > limit {
		clear(contents)
		return nil, errors.New("cannot read bounded local file")
	}
	return contents, nil
}

// PrivateDir prepares a directory using the process's normal filesystem access.
func PrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("local state path must be a directory without a reparse point")
	}
	return nil
}

// CreateTemp creates a new temporary file in directory.
func CreateTemp(directory, pattern string) (*os.File, error) {
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
		handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
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
