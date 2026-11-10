package privatefs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivatePathsAreCreatedRestrictedAndNeverReACLExisting(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private")
	if err := EnsureDirectory(path); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "key")
	if err := os.WriteFile(file, []byte("private-test-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(file); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(root, "public-fixture")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	broad, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := broad.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(public, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(public, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureDirectory(public); err == nil {
		t.Fatal("accepted inherited broad fixture directory")
	}
	after, err := windows.GetNamedSecurityInfo(public, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || before.String() != after.String() {
		t.Fatal("changed existing directory ACL", err)
	}
	if err := EnsureDirectory(path); err != nil {
		t.Fatal("private directory not reusable:", err)
	}
}

func TestPrivateFileRejectsForeignOwnerAndBroadGrants(t *testing.T) {
	sid, err := UserSID()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := windows.SecurityDescriptorFromString("O:S-1-5-32-546D:P(A;;FA;;;" + sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	if CheckFileDescriptor(foreign) == nil {
		t.Fatal("foreign default owner accepted")
	}
	broad, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;WD)(A;;FA;;;" + sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	if CheckFileDescriptor(broad) == nil {
		t.Fatal("foreign DACL grant accepted")
	}
	defaultOwner, err := defaultOwnerSID()
	if err != nil {
		t.Fatal(err)
	}
	owned, err := windows.SecurityDescriptorFromString("O:" + defaultOwner.String() + "D:P(A;;FA;;;" + sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckFileDescriptor(owned); err != nil {
		t.Fatal("current token's exact default owner rejected:", err)
	}
	if !windows.EqualSid(defaultOwner, sid) && CheckDescriptor(owned) == nil {
		t.Fatal("pipe owner authentication accepted a group owner")
	}
}
