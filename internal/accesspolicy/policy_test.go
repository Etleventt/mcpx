package accesspolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	home, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = protectCreated(home, true); e != nil {
		t.Fatal(e)
	}
	return &Store{Home: home, LegacyPassword: "original-fixed-password"}
}
func TestTemporaryLifecycle(t *testing.T) {
	s := testStore(t)
	before, e := s.Status()
	if e != nil || before.Enabled {
		t.Fatalf("initial status: %v", e)
	}
	st, code, e := s.CreateTemporary()
	if e != nil || !st.TemporaryActive || code == "" {
		t.Fatalf("create: %v", e)
	}
	g, e := s.Verify(code)
	if e != nil || !s.Valid(g) {
		t.Fatalf("verify: %v", e)
	}
	if _, e = s.Verify(code); !errors.Is(e, ErrDenied) {
		t.Fatal("one-use code replay accepted")
	}
	restarted := &Store{Home: s.Home, LegacyPassword: s.LegacyPassword}
	if !restarted.Valid(g) {
		t.Fatal("valid grant should survive restart")
	}
	if _, e = restarted.RevokeTemporary(); e != nil {
		t.Fatal(e)
	}
	if s.Valid(g) || restarted.Valid(g) {
		t.Fatal("revoked grant survived")
	}
	if _, e = s.Verify(s.LegacyPassword); e != nil {
		t.Fatal("temporary change damaged fixed password")
	}
}
func TestExpiryRegenerationAndFixedRevocation(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	s.Now = func() time.Time { return now }
	_, code, e := s.CreateTemporary()
	if e != nil {
		t.Fatal(e)
	}
	g, e := s.Verify(code)
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(TemporaryTTL)
	if s.Valid(g) {
		t.Fatal("grant survived exact expiry")
	}
	_, second, e := s.CreateTemporary()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Verify(code); e == nil {
		t.Fatal("old code survived generation")
	}
	g2, e := s.Verify(second)
	if e != nil {
		t.Fatal(e)
	}
	fixed, e := s.Verify(s.LegacyPassword)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.SetFixed("new-independent-password"); e != nil {
		t.Fatal(e)
	}
	if s.Valid(fixed) || s.Valid(Grant{}) {
		t.Fatal("old fixed grants survived password change")
	}
	if !s.Valid(g2) {
		t.Fatal("fixed password change should not silently revoke temporary grant")
	}
	if _, e = s.Verify(s.LegacyPassword); e == nil {
		t.Fatal("legacy password fallback after change")
	}
	if _, e = s.Verify("new-independent-password"); e != nil {
		t.Fatal(e)
	}
}
func TestConcurrentSingleUseAndRateLimit(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	s.Now = func() time.Time { return now }
	_, code, e := s.CreateTemporary()
	if e != nil {
		t.Fatal(e)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other := &Store{Home: s.Home, LegacyPassword: s.LegacyPassword, Now: s.Now}
			if _, e := other.Verify(code); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("success count %d", successes.Load())
	}
	// A denied lock acquisition never examined the password and is not an
	// attempt. Complete ten serial attempts independently of scheduler timing.
	for i := 0; i < 10; i++ {
		_, err := s.Verify("incorrect")
		if !errors.Is(err, ErrDenied) && !errors.Is(err, ErrLimited) {
			t.Fatalf("unexpected serial rejection: %v", err)
		}
	}
	restarted := &Store{Home: s.Home, LegacyPassword: s.LegacyPassword, Now: s.Now}
	if _, e = restarted.Verify(s.LegacyPassword); !errors.Is(e, ErrLimited) {
		t.Fatalf("guess bound lost: %v", e)
	}
}
func TestCorruptionAndMissingStateFailClosed(t *testing.T) {
	for _, kind := range []string{"corrupt", "missing", "directory"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			_, code, e := s.CreateTemporary()
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(s.Home, "access-policy", "policy.json")
			if kind == "corrupt" {
				e = os.WriteFile(path, []byte("{}"), 0o600)
			} else if kind == "missing" {
				e = os.Remove(path)
			} else {
				e = os.Rename(filepath.Dir(path), filepath.Dir(path)+".preserved")
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Status(); e == nil {
				t.Fatal("unsafe state returned status")
			}
			if _, e = s.Verify(code); e == nil {
				t.Fatal("unsafe state authorized")
			}
			if _, e = s.Verify(s.LegacyPassword); e == nil {
				t.Fatal("unsafe state fell back to legacy")
			}
		})
	}
}
func TestStoredSecretsAndInputValidation(t *testing.T) {
	s := testStore(t)
	_, code, e := s.CreateTemporary()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(s.Home, "access-policy", "policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), code) || strings.Contains(string(raw), s.LegacyPassword) {
		t.Fatal("plaintext secret persisted")
	}
	for _, password := range []string{"short", "long-enough\npassword", strings.Repeat("x", 1025)} {
		if _, e = s.SetFixed(password); e == nil {
			t.Fatal("bad fixed password accepted")
		}
	}
}
