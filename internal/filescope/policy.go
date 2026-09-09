// Package filescope implements a file-only boundary. It never executes programs.
package filescope

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"mcpx/internal/accesspolicy"
)

const Full = "full"
const Folders = "folders"
const Version = 1

var ErrDenied = errors.New("filesystem scope denied")
var ErrState = errors.New("filesystem scope state unavailable; access denied")

type RootSpec struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Identity string `json:"identity,omitempty"`
}
type Policy struct {
	Version    int        `json:"version"`
	Mode       string     `json:"mode"`
	Generation string     `json:"generation"`
	Roots      []RootSpec `json:"roots"`
}
type Store struct{ Home string }

func Available() bool              { return runtime.GOOS == "darwin" || runtime.GOOS == "linux" }
func (s Store) dir() string        { return filepath.Join(s.Home, "filesystem-scope") }
func TokenPath(home string) string { return filepath.Join(home, "filesystem-scope", "control-token") }
func randomID() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func (s Store) Ensure() (string, error) {
	if accesspolicy.CheckHome(s.Home) != nil {
		return "", ErrState
	}
	if e := os.Mkdir(s.dir(), 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return "", e
	}
	if accesspolicy.CheckHome(s.dir()) != nil {
		return "", ErrState
	}
	if b, e := accesspolicy.ReadPrivate(TokenPath(s.Home)); e == nil {
		if len(b) != 64 {
			return "", ErrState
		}
		return string(b), nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", ErrState
	}
	token, e := randomID()
	if e != nil {
		return "", e
	}
	f, e := os.OpenFile(TokenPath(s.Home), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", e
	}
	if _, e = f.WriteString(token); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return "", e
	}
	if ce != nil {
		return "", ce
	}
	return token, nil
}
func (s Store) Load() (Policy, error) {
	fallback := Policy{Version: Version, Mode: Full, Generation: "legacy", Roots: []RootSpec{}}
	if s.Home == "" {
		return fallback, nil
	}
	raw, e := accesspolicy.ReadPrivate(filepath.Join(s.dir(), "policy.json"))
	if errors.Is(e, os.ErrNotExist) {
		_, marker := os.Lstat(filepath.Join(s.Home, "filesystem-scope.enabled"))
		if errors.Is(marker, os.ErrNotExist) {
			return fallback, nil
		}
		return Policy{}, ErrState
	}
	if e != nil {
		return Policy{}, ErrState
	}
	var p Policy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || p.Version != Version || (p.Mode != Full && p.Mode != Folders) || len(p.Generation) != 64 || len(p.Roots) > 64 {
		return Policy{}, ErrState
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Policy{}, ErrState
	}
	generation, err := hex.DecodeString(p.Generation)
	if err != nil || len(generation) != 32 {
		return Policy{}, ErrState
	}
	if p.Mode == Folders && !Available() {
		return Policy{}, ErrState
	}
	seen := map[string]bool{}
	for _, root := range p.Roots {
		if root.Name == "" || len(root.Name) > 128 || seen[root.Name] || !filepath.IsAbs(root.Path) || root.Path != filepath.Clean(root.Path) || root.Identity == "" || contains(root.Path, s.Home) || contains(s.Home, root.Path) {
			return Policy{}, ErrState
		}
		seen[root.Name] = true
	}
	return p, nil
}
func (p Policy) Digest() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func contains(root, path string) bool {
	r, e := filepath.Rel(root, path)
	return e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r)
}
func (s Store) Save(mode string, roots []RootSpec) (Policy, error) {
	if mode != Full && mode != Folders {
		return Policy{}, ErrDenied
	}
	if mode == Folders && !Available() {
		return Policy{}, ErrDenied
	}
	if len(roots) > 64 {
		return Policy{}, ErrDenied
	}
	if _, e := s.Ensure(); e != nil {
		return Policy{}, e
	}
	home, e := filepath.EvalSymlinks(s.Home)
	if e != nil {
		return Policy{}, e
	}
	p := Policy{Version: Version, Mode: mode, Roots: []RootSpec{}}
	seen := map[string]bool{}
	if mode == Folders {
		for _, root := range roots {
			if root.Name == "" || len(root.Name) > 128 || seen[root.Name] || !filepath.IsAbs(root.Path) {
				return Policy{}, ErrDenied
			}
			seen[root.Name] = true
			path, e := filepath.EvalSymlinks(root.Path)
			if e != nil {
				return Policy{}, ErrDenied
			}
			// Runtime credentials/policy cannot be authorized through a parent directory.
			if contains(path, home) || contains(home, path) {
				return Policy{}, ErrDenied
			}
			info, e := os.Stat(path)
			if e != nil || !info.IsDir() {
				return Policy{}, ErrDenied
			}
			id, e := identity(info)
			if e != nil {
				return Policy{}, e
			}
			p.Roots = append(p.Roots, RootSpec{Name: root.Name, Path: path, Identity: id})
		}
	}
	p.Generation, e = randomID()
	if e != nil {
		return Policy{}, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return Policy{}, e
	}
	// The marker is durable before replacing policy, so a missing policy fails closed.
	marker := filepath.Join(s.Home, "filesystem-scope.enabled")
	f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e == nil {
		_, e = f.WriteString("1\n")
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return Policy{}, e
		}
		if ce != nil {
			return Policy{}, ce
		}
	} else if !errors.Is(e, os.ErrExist) {
		return Policy{}, e
	}
	directory, syncErr := os.Open(s.Home)
	if syncErr != nil {
		return Policy{}, syncErr
	}
	syncErr = directory.Sync()
	directory.Close()
	if syncErr != nil {
		return Policy{}, syncErr
	}
	f, e = os.CreateTemp(s.dir(), ".policy-")
	if e != nil {
		return Policy{}, e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return Policy{}, e
	}
	if ce != nil {
		return Policy{}, ce
	}
	if e = os.Rename(f.Name(), filepath.Join(s.dir(), "policy.json")); e != nil {
		return Policy{}, e
	}
	d, e := os.Open(s.dir())
	if e == nil {
		e = d.Sync()
		d.Close()
	}
	return p, e
}
func (p Policy) Open(name string) (*os.Root, RootSpec, error) {
	if p.Mode != Folders {
		return nil, RootSpec{}, ErrDenied
	}
	for _, spec := range p.Roots {
		if spec.Name == name {
			root, e := os.OpenRoot(spec.Path)
			if e != nil {
				return nil, spec, ErrDenied
			}
			info, e := root.Stat(".")
			if e != nil {
				root.Close()
				return nil, spec, ErrDenied
			}
			id, e := identity(info)
			if e != nil || id != spec.Identity {
				root.Close()
				return nil, spec, fmt.Errorf("authorized folder changed; select it again locally")
			}
			return root, spec, nil
		}
	}
	return nil, RootSpec{}, ErrDenied
}
