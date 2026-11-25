package xrayflow

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateSocketDirectory(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	for index := range uint32(acl.AceCount) {
		var entry *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &entry) != nil || entry == nil {
			return false
		}
		if entry.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if entry.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&entry.SidStart))
		if !sid.Equals(user.User.Sid) && !sid.IsWellKnown(windows.WinLocalSystemSid) &&
			!sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return false
		}
	}
	return true
}

// MakePrivateWindowsDirectory creates a directory with a protected ACL for
// the current user, Administrators and SYSTEM, including its future files.
func MakePrivateWindowsDirectory(path string) error {
	if privateSocketDirectory(path) {
		return nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd,
	}); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	if !privateSocketDirectory(path) {
		return errors.New("Hydrat requires an access-restricted local Windows directory")
	}
	return nil
}

// On Windows the socket inherits the restricted parent DACL.
func secureSocket(string) error { return nil }
