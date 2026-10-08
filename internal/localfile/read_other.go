//go:build !linux && !darwin && !windows

package localfile

import "errors"

func Read(string, int64, bool) ([]byte, error) {
	return nil, errors.New("secure local files require Linux or macOS")
}
