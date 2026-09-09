//go:build darwin || linux

package filescope

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func fixture(t *testing.T) (Store, string, string) {
	t.Helper()
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	home, allowed, out := filepath.Join(base, "runtime"), filepath.Join(base, "allowed"), filepath.Join(base, "outside")
	for _, p := range []string{home, allowed, out} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	return Store{Home: home}, allowed, out
}
func write(t *testing.T, p, s string) {
	t.Helper()
	if e := os.WriteFile(p, []byte(s), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestFileScopePolicyRoundTripAndFailClosed(t *testing.T) {
	store, dir, _ := fixture(t)
	p, e := store.Load()
	if e != nil || p.Mode != Full {
		t.Fatal("initial state must be explicit full", e)
	}
	p, e = store.Save(Folders, []RootSpec{{Name: "demo", Path: dir}})
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := store.Load()
	if e != nil || loaded.Digest() != p.Digest() {
		t.Fatal("save/load mismatch", e)
	}
	if _, e = store.Save(Folders, []RootSpec{{Name: "home", Path: filepath.Dir(store.Home)}}); e == nil {
		t.Fatal("runtime credential parent authorized")
	}
	if _, e = store.Save(Folders, []RootSpec{{Name: "state", Path: store.Home}}); e == nil {
		t.Fatal("runtime state authorized")
	}
	raw, e := os.ReadFile(filepath.Join(store.dir(), "policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"{}", string(raw) + " {}", strings.Replace(string(raw), `"mode":"folders"`, `"mode":"typo"`, 1), strings.Replace(string(raw), `"version":1`, `"version":1,"extra":true`, 1)} {
		write(t, filepath.Join(store.dir(), "policy.json"), bad)
		if _, e := store.Load(); e == nil {
			t.Fatal("malformed policy accepted")
		}
	}
	if e = os.Remove(filepath.Join(store.dir(), "policy.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = store.Load(); e == nil {
		t.Fatal("missing policy silently became full")
	}
	p, e = store.Save(Folders, nil)
	if e != nil || len(p.Roots) != 0 {
		t.Fatal(e)
	}
	if _, _, e = p.Open("demo"); e == nil {
		t.Fatal("empty allowlist allowed access")
	}
	p, e = store.Save(Full, nil)
	if e != nil || p.Mode != Full {
		t.Fatal(e)
	}
}
func TestRootedAccessDeniesEscapeLinksAndSpecialFiles(t *testing.T) {
	store, dir, out := fixture(t)
	write(t, filepath.Join(dir, "inside.txt"), "inside")
	write(t, filepath.Join(out, "canary.txt"), "outside-secret")
	if e := os.Symlink(out, filepath.Join(dir, "escape")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(out, "canary.txt"), filepath.Join(dir, "file-link")); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(filepath.Join(out, "canary.txt"), filepath.Join(dir, "hard-link")); e != nil {
		t.Fatal(e)
	}
	if e := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0600); e != nil {
		t.Fatal(e)
	}
	p, e := store.Save(Folders, []RootSpec{{Name: "demo", Path: dir}})
	if e != nil {
		t.Fatal(e)
	}
	root, _, e := p.Open("demo")
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	for _, path := range []string{"../outside/canary.txt", out + "/canary.txt", "escape/canary.txt", "file-link", "hard-link", "pipe", "."} {
		if raw, _, e := Read(root, path); e == nil {
			t.Fatalf("unsafe read %q returned %q", path, raw)
		}
	}
	if raw, _, e := Read(root, "inside.txt"); e != nil || string(raw) != "inside" {
		t.Fatal("allowed file denied", e)
	}
	scan, e := Scan(root, nil, "outside-secret", false, 100, nil)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(scan)
	if strings.Contains(string(encoded), "outside-secret") {
		t.Fatal("search escaped allowlist")
	}
	for _, path := range []string{"../outside/new.txt", "escape/new.txt", out + "/new.txt", "file-link", "hard-link"} {
		if _, e := EditOne(root, Edit{Operation: "create", Path: path, Content: "bad"}); e == nil {
			t.Fatalf("unsafe create %q accepted", path)
		}
	}
	current, _ := os.ReadFile(filepath.Join(out, "canary.txt"))
	if string(current) != "outside-secret" {
		t.Fatal("outside modified")
	}
	if _, e := EditOne(root, Edit{Operation: "replace_exact", Path: "inside.txt", BaseSHA256: SHA([]byte("inside")), Match: "inside", Replacement: "changed"}); e != nil {
		t.Fatal(e)
	}
	if _, e := EditOne(root, Edit{Operation: "replace_exact", Path: "inside.txt", BaseSHA256: SHA([]byte("inside")), Match: "changed", Replacement: "stale"}); e == nil {
		t.Fatal("stale edit accepted")
	}
	if _, e := EditOne(root, Edit{Operation: "create", Path: "nested/new.txt", Content: "new"}); e != nil {
		t.Fatal(e)
	}
}
func TestRootIdentityAndConcurrentParentSubstitution(t *testing.T) {
	store, dir, out := fixture(t)
	write(t, filepath.Join(out, "probe"), "outside-secret")
	p, e := store.Save(Folders, []RootSpec{{Name: "demo", Path: dir}})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(dir, dir+"-original"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if root, _, e := p.Open("demo"); e == nil {
		root.Close()
		t.Fatal("replacement root accepted")
	}
	p, e = store.Save(Folders, []RootSpec{{Name: "demo", Path: dir}})
	if e != nil {
		t.Fatal(e)
	}
	root, _, e := p.Open("demo")
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	parent := filepath.Join(dir, "moving")
	if e = os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(parent, "probe"), "inside")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			os.Rename(parent, parent+"-safe")
			os.Symlink(out, parent)
			os.Remove(parent)
			os.Rename(parent+"-safe", parent)
		}
	}()
	for i := 0; i < 400; i++ {
		raw, _, e := Read(root, "moving/probe")
		if e == nil && string(raw) != "inside" {
			t.Errorf("concurrent parent escape read %q", raw)
		}
	}
	wg.Wait()
}
