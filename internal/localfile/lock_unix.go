//go:build linux || darwin

package localfile

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Lock exclusively locks a persistent, private regular file. Never unlink this
// file: unlinking lets two processes lock different inodes for the same path.
// The caller must use a private directory and bound the acquisition context.
func Lock(ctx context.Context, path string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("cannot open private lock file")
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("unsafe private lock file")
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return nil, err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = file.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			_ = file.Close()
			return nil, errors.New("cannot acquire private lock")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// PrivateDir creates a directory and validates its final component without
// following symlinks, then restricts its permissions through the opened handle.
func PrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return errors.New("cannot create private directory")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("cannot open private directory")
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe private directory")
	}
	if unix.Fchmod(fd, 0700) != nil {
		return errors.New("cannot restrict private directory")
	}
	return nil
}
