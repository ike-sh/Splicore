// Package privatefs implements owner-restricted Windows state and key paths.
// It never changes permissions on an existing path.
package privatefs

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"golang.org/x/sys/windows"
)

func UserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func Descriptor(inherit bool) (string, error) {
	sid, err := UserSID()
	if err != nil {
		return "", err
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	return "O:" + sid.String() + "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;" + sid.String() + ")", nil
}

func defaultOwnerSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	var needed uint32
	if err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &needed); err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, identity.Err(identity.Unavailable, "cannot inspect process token owner")
	}
	if needed < uint32(unsafe.Sizeof(uintptr(0))) {
		return nil, identity.Err(identity.Unavailable, "cannot inspect process token owner")
	}
	buffer := make([]byte, needed)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], needed, &needed); err != nil {
		return nil, err
	}
	// TOKEN_OWNER contains a SID pointer into this buffer; return an owned copy.
	owner := *(**windows.SID)(unsafe.Pointer(&buffer[0]))
	if owner == nil {
		return nil, identity.Err(identity.Unavailable, "cannot inspect process token owner")
	}
	return owner.Copy()
}

// CheckDescriptor rejects null DACLs, foreign ownership, broad grants and ACE
// types this policy cannot prove safe. SYSTEM is an OS principal, not a user group.
func CheckDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	return checkDescriptor(sd, false)
}

// Windows may use a token's default owner (for example Administrators for an
// elevated token) for files created by that process. Accept only that exact OS
// identity in addition to its user; DACL grants remain user/SYSTEM only. Pipe
// authentication deliberately uses CheckDescriptor's stricter user-only owner.
func CheckFileDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	return checkDescriptor(sd, true)
}

func checkDescriptor(sd *windows.SECURITY_DESCRIPTOR, file bool) error {
	sid, err := UserSID()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return identity.Err(identity.Invalid, "private file owner or permissions invalid")
	}
	owned := windows.EqualSid(owner, sid)
	if !owned && file {
		defaultOwner, err := defaultOwnerSID()
		owned = err == nil && defaultOwner != nil && windows.EqualSid(owner, defaultOwner)
	}
	if !owned {
		return identity.Err(identity.Invalid, "private file owner or permissions invalid")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return identity.Err(identity.Invalid, "private file owner or permissions invalid")
	}
	ownerGrant := false
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(i), &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return identity.Err(identity.Invalid, "private file owner or permissions invalid")
		}
		grantee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		current := windows.EqualSid(grantee, sid)
		if !current && !grantee.IsWellKnown(windows.WinLocalSystemSid) {
			return identity.Err(identity.Invalid, "private file owner or permissions invalid")
		}
		const fileAllAccess uint32 = 0x001f01ff // Windows FILE_ALL_ACCESS / SDDL FA
		ownerGrant = ownerGrant || current && uint32(ace.Mask)&fileAllAccess == fileAllAccess
	}
	if !ownerGrant {
		return identity.Err(identity.Invalid, "private file owner or permissions invalid")
	}
	return nil
}

func check(path string, directory bool) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return identity.Err(identity.Invalid, "private file owner or permissions invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.EqualFold(resolved, filepath.Clean(path)) {
		return identity.Err(identity.Invalid, "private file owner or permissions invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || info.IsDir() != directory || !directory && !info.Mode().IsRegular() {
		return identity.Err(identity.Invalid, "private file owner or permissions invalid")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return CheckFileDescriptor(sd)
}

func CheckDirectory(path string) error { return check(path, true) }
func CheckFile(path string) error      { return check(path, false) }

// EnsureDirectory gives new directories their DACL atomically at creation.
// Existing directories must already satisfy the policy; they are never re-ACL'd.
func EnsureDirectory(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return identity.Err(identity.Invalid, "private directory owner or permissions invalid")
	}
	if _, err := os.Lstat(path); err == nil {
		return CheckDirectory(path)
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if _, err := os.Lstat(parent); os.IsNotExist(err) {
		if err := EnsureDirectory(parent); err != nil {
			return err
		}
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || !strings.EqualFold(resolved, parent) {
		return identity.Err(identity.Invalid, "private directory owner or permissions invalid")
	}
	sddl, err := Descriptor(true)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, sa); err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	return CheckDirectory(path)
}
