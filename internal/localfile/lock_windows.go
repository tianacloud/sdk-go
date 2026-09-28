//go:build windows

package localfile

import (
	"context"
	"errors"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openLock(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	sd, err := privateDescriptor()
	if err != nil {
		return windows.InvalidHandle, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	// Deny deletion while open so all contenders keep the persistent file identity.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attrs, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return windows.InvalidHandle, errors.New("cannot open private lock file")
	}
	info, err := fileInfo(handle, true)
	if err != nil || info.NumberOfLinks != 1 || checkPrivate(handle) != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, errors.New("unsafe private lock file")
	}
	return handle, nil
}

// Lock holds a persistent file lock until release or process exit. Acquisition
// polls only a nonblocking LockFileEx call so the context bounds contention.
func Lock(ctx context.Context, path string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle, err := openLock(path)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			windows.CloseHandle(handle)
			return nil, err
		}
		err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
		if err == nil {
			file := os.NewFile(uintptr(handle), path)
			return func() { _ = file.Close() }, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			windows.CloseHandle(handle)
			return nil, errors.New("cannot acquire private lock")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			windows.CloseHandle(handle)
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
