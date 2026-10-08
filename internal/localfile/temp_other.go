//go:build !windows

package localfile

import "os"

func CreateTemp(directory, pattern string) (*os.File, error) {
	return os.CreateTemp(directory, pattern)
}
