package oauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefreshGrantsPersistRotateAndReplayAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refresh.json")
	secret := []byte(strings.Repeat("x", 32))
	newServer := func() *Server {
		s := NewServer("test-password", "https://runtime.test", secret, 3600)
		if err := s.Registry.AddPreregistered("client", []string{"http://127.0.0.1/cb"}, ""); err != nil {
			t.Fatal(err)
		}
		if err := s.SetRefreshPersistPath(path); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := newServer()
	old := first.IssueRefreshToken("client", "https://runtime.test/mcp", DefaultScope)
	if old == "" {
		t.Fatal("could not issue refresh token")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), old) {
		t.Fatal("refresh token leaked to persistent store")
	}
	restarted := newServer()
	access, ttl, next, err := restarted.ExchangeRefreshToken(old, "client", "")
	if err != nil || access == "" || next == "" || ttl <= 0 {
		t.Fatalf("refresh after restart: %v", err)
	}
	last := newServer()
	if _, _, _, err := last.ExchangeRefreshToken(old, "client", ""); err == nil {
		t.Fatal("old token replay accepted after restart")
	}
	if _, _, _, err := last.ExchangeRefreshToken(next, "other-client", ""); err == nil {
		t.Fatal("wrong client accepted")
	}
	if _, _, next2, err := last.ExchangeRefreshToken(next, "client", ""); err != nil || next2 == "" {
		t.Fatalf("rotated token unavailable after restart: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("refresh store must be private, info=%v err=%v", info, err)
	}
}

func TestTwoOAuthProcessesCannotReplayOrLoseRefreshTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refresh.json")
	newServer := func() *Server {
		s := NewServer("password", "https://runtime.test", []byte(strings.Repeat("x", 32)), 3600)
		if err := s.Registry.AddPreregistered("client", []string{"http://127.0.0.1/cb"}, ""); err != nil {
			t.Fatal(err)
		}
		if err := s.SetRefreshPersistPath(path); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := newServer()
	second := newServer()
	firstToken := first.IssueRefreshToken("client", "https://runtime.test/mcp", DefaultScope)
	secondToken := second.IssueRefreshToken("client", "https://runtime.test/mcp", DefaultScope)
	if firstToken == "" || secondToken == "" {
		t.Fatal("cannot issue tokens")
	}
	restarted := newServer()
	_, _, rotated, err := restarted.ExchangeRefreshToken(firstToken, "client", "")
	if err != nil || rotated == "" {
		t.Fatalf("first token lost when second process issued: %v", err)
	}
	if _, _, _, err := first.ExchangeRefreshToken(firstToken, "client", ""); err == nil {
		t.Fatal("stale process replayed already rotated refresh token")
	}
	if _, _, _, err := second.ExchangeRefreshToken(secondToken, "client", ""); err != nil {
		t.Fatalf("second token lost during cross-process rotation: %v", err)
	}
}

func TestParallelOAuthRefreshHasExactlyOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refresh.json")
	newServer := func() *Server {
		s := NewServer("password", "https://runtime.test", []byte(strings.Repeat("x", 32)), 3600)
		if err := s.Registry.AddPreregistered("client", []string{"http://127.0.0.1/cb"}, ""); err != nil {
			t.Fatal(err)
		}
		if err := s.SetRefreshPersistPath(path); err != nil {
			t.Fatal(err)
		}
		return s
	}
	token := newServer().IssueRefreshToken("client", "https://runtime.test/mcp", DefaultScope)
	if token == "" {
		t.Fatal("token not issued")
	}
	first, second := newServer(), newServer()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, server := range []*Server{first, second} {
		s := server
		go func() {
			<-start
			_, _, _, err := s.ExchangeRefreshToken(token, "client", "")
			results <- err
		}()
	}
	close(start)
	a, b := <-results, <-results
	if (a == nil) == (b == nil) {
		t.Fatalf("expected exactly one refresh success, got errors %v / %v", a, b)
	}
}

func TestRefreshPersistenceFailureDoesNotIssueOrConsume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "refresh.json")
	s := NewServer("pw", "https://runtime.test", []byte(strings.Repeat("x", 32)), 3600)
	if err := s.SetRefreshPersistPath(path); err != nil {
		t.Fatal(err)
	}
	old := s.IssueRefreshToken("client", "https://runtime.test/mcp", DefaultScope)
	if old == "" {
		t.Fatal("initial issue failed")
	}
	// The destination is now a directory, so atomic rename must fail.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if unexpected := s.IssueRefreshToken("client", "https://runtime.test/mcp", DefaultScope); unexpected != "" {
		t.Fatal("issued refresh token when persistence failed")
	}
	if _, _, next, err := s.ExchangeRefreshToken(old, "client", ""); err == nil || next != "" {
		t.Fatal("rotation succeeded despite persistence failure")
	}
}

func TestTemporaryGrantDoesNotBecomePermanentAfterRestart(t *testing.T) {
	s := accessServer(t)
	path := filepath.Join(t.TempDir(), "refresh.json")
	if err := s.SetRefreshPersistPath(path); err != nil {
		t.Fatal(err)
	}
	_, credential, err := s.Access.CreateTemporary()
	if err != nil {
		t.Fatal(err)
	}
	code := authorizeAccess(t, s, credential)
	_, token, _ := exchangeAccess(t, s, code)
	restarted := NewServer(s.Password, s.ServerURL, s.TokenSecret, s.TokenTTL)
	restarted.Access = s.Access
	if err := restarted.SetRefreshPersistPath(path); err != nil {
		t.Fatal(err)
	}
	_, _, next, err := restarted.ExchangeRefreshToken(token, "desktop-test", "")
	if err != nil || next == "" {
		t.Fatalf("temporary grant did not survive restart within its bound: %v", err)
	}
	// Revocation must remain authoritative after the next process restart.
	if _, err := s.Access.RevokeTemporary(); err != nil {
		t.Fatal(err)
	}
	afterRevoke := NewServer(s.Password, s.ServerURL, s.TokenSecret, s.TokenTTL)
	afterRevoke.Access = s.Access
	if err := afterRevoke.SetRefreshPersistPath(path); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := afterRevoke.ExchangeRefreshToken(next, "desktop-test", ""); err == nil {
		t.Fatal("revoked temporary grant survived restart")
	}
}
