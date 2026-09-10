//go:build windows

package accesspolicy

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateDACLCanonicalForms(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	ace := "(A;;FA;;;" + user.User.Sid.String() + ")"
	for _, tc := range []struct {
		name, sddl string
		want       bool
	}{
		{"original", "D:P" + ace + "(A;;FA;;;SY)", true},
		{"canonical", "D:PAI(A;;FA;;;SY)" + ace, true},
		{"extra-reader", "D:P" + ace + "(A;;FA;;;SY)(A;;FR;;;WD)", false},
		{"inherited-user", "D:P(A;ID;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)", false},
		{"unprotected", "D:" + ace + "(A;;FA;;;SY)", false},
		{"missing-system", "D:P" + ace, false},
		{"wrong-user", "D:P(A;;FA;;;BU)(A;;FA;;;SY)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if got := privateDACL(sd, user.User.Sid); got != tc.want {
				t.Fatalf("accepted=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestWindowsCreatedPolicyHasUserOwner(t *testing.T) {
	s := testStore(t)
	if err := CheckHome(s.Home); err != nil {
		t.Fatal(err)
	}
	status, token, err := s.GenerateMCPToken()
	if err != nil || !status.MCPTokenSet || len(token) != 56 {
		t.Fatalf("generation failed: %v", err)
	}
	for _, name := range []string{"access-policy", "access-policy/lock", "access-policy/policy.json", "access-policy.enabled"} {
		path := filepath.Join(s.Home, filepath.FromSlash(name))
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = checkOwner(path, info, true); err != nil {
			t.Fatalf("invalid created ownership: %s", name)
		}
	}
	if _, err = s.RevokeMCPToken(); err != nil {
		t.Fatal(err)
	}
}
