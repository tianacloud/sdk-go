//go:build !windows

package auth_test

import "os"

var writeFixtureFile = os.WriteFile
var chmodFixtureFile = os.Chmod
