//go:build !linux && !darwin && !windows

package localfile

import (
	"context"
	"errors"
)

func Lock(context.Context, string) (func(), error) {
	return nil, errors.New("secure local files require Linux or macOS")
}
func PrivateDir(string) error { return errors.New("secure local files require Linux or macOS") }
