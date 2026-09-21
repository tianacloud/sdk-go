//go:build linux || darwin

package localfile

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestReadRejectsFIFOAndDirectories(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, dir} {
		if _, err := Read(path, 64, true); err == nil {
			t.Fatal("accepted non-regular file")
		}
	}
	path := filepath.Join(dir, "large")
	if err := os.WriteFile(path, make([]byte, 65), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64, true); err == nil {
		t.Fatal("accepted oversized file")
	}
}
