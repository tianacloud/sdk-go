//go:build linux || darwin

package localfile

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

// Read opens once without following a final symlink or blocking on a FIFO.
// Private files must belong to the current user and have exactly mode 0600.
func Read(path string, limit int64, private bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > limit || (private && (st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()))) {
		return nil, errors.New("unsafe local file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		clear(b)
		return nil, errors.New("cannot read bounded local file")
	}
	return b, nil
}
