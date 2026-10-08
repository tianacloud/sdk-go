//go:build windows

package auth

import (
	"golang.org/x/sys/windows"
	"os"
)

func writeFixtureFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return chmodFixtureFile(path, mode)
}

func chmodFixtureFile(path string, mode os.FileMode) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sddl := "D:P(A;;FA;;;" + user.User.Sid.String() + ")"
	if mode.Perm()&0077 != 0 {
		sddl += "(A;;FR;;;WD)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, acl, nil)
}
