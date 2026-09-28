//go:build !windows

package auth

import "os"

var writeFixtureFile = os.WriteFile
var chmodFixtureFile = os.Chmod
