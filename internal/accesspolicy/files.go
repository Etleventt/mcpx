package accesspolicy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Existing paths are validated, never chmodded into apparent safety.
func checkPath(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return ErrState
	}
	for {
		info, err := os.Lstat(path)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || isReparse(path) {
				return ErrState
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return ErrState
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
func CheckHome(home string) error {
	if !filepath.IsAbs(home) || checkPath(home) != nil {
		return ErrState
	}
	info, err := os.Lstat(home)
	if err != nil || !info.IsDir() || checkOwner(home, info, false) != nil {
		return ErrState
	}
	return nil
}
func ReadPrivate(path string) ([]byte, error) {
	if checkPath(path) != nil {
		return nil, ErrState
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 || checkOwner(path, info, true) != nil {
		return nil, ErrState
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrState
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, ErrState
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, ErrState
	}
	return raw, nil
}
func writePrivate(path string, raw []byte) error {
	if checkPath(path) != nil {
		return ErrState
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".access-next-")
	if err != nil {
		return ErrState
	}
	defer os.Remove(f.Name())
	if protectCreated(f.Name(), false) != nil {
		f.Close()
		return ErrState
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrState
	}
	if replacePrivate(f.Name(), path) != nil || syncDirectory(filepath.Dir(path)) != nil {
		return ErrState
	}
	return nil
}
func validHex(v string, n int) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == n && hex.EncodeToString(b) == v
}
func readPolicy(path string) (*policy, error) {
	raw, err := ReadPrivate(path)
	if err != nil {
		return nil, ErrState
	}
	var p policy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return nil, ErrState
	}
	var extra any
	if d.Decode(&extra) != io.EOF || p.Version != 1 || !validHex(p.Salt, 16) || !validHex(p.FixedHash, 32) || (p.FixedGeneration != "" && !validHex(p.FixedGeneration, 16)) || p.Attempts < 0 || p.Attempts > 10 || p.Window < 0 {
		return nil, ErrState
	}
	if p.TemporaryGeneration == "" {
		if p.TemporaryHash != "" || p.TemporaryUntil != 0 {
			return nil, ErrState
		}
	} else if !validHex(p.TemporaryGeneration, 16) || !validHex(p.TemporaryHash, 32) || p.TemporaryUntil <= 0 {
		return nil, ErrState
	}
	return &p, nil
}

func (s *Store) withPolicy(create bool, fn func(*policy) (bool, error)) error {
	if CheckHome(s.Home) != nil {
		return ErrState
	}
	dir := filepath.Join(s.Home, "access-policy")
	marker := filepath.Join(s.Home, "access-policy.enabled")
	if checkPath(dir) != nil || checkPath(marker) != nil {
		return ErrState
	}
	info, err := os.Lstat(dir)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Lstat(marker); !errors.Is(e, os.ErrNotExist) {
			return ErrState
		}
		if !create {
			_, e := fn(nil)
			return e
		}
		if err = os.Mkdir(dir, 0o700); err == nil {
			created = true
			if protectCreated(dir, true) != nil {
				return ErrState
			}
		} else if !errors.Is(err, os.ErrExist) {
			return ErrState
		}
		info, err = os.Lstat(dir)
	}
	if err != nil || !info.IsDir() || checkOwner(dir, info, true) != nil {
		return ErrState
	}
	lockPath := filepath.Join(dir, "lock")
	if checkPath(lockPath) != nil {
		return ErrState
	}
	flags := os.O_RDWR
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(lockPath, flags, 0o600)
	if err != nil {
		return ErrState
	}
	defer f.Close()
	if created && protectCreated(lockPath, false) != nil {
		return ErrState
	}
	fi, e := f.Stat()
	li, lerr := os.Lstat(lockPath)
	if e != nil || lerr != nil || !fi.Mode().IsRegular() || !os.SameFile(fi, li) || checkOwner(lockPath, fi, true) != nil {
		return ErrState
	}
	deadline := time.Now().Add(3 * time.Second)
	for lockFile(f) != nil {
		if time.Now().After(deadline) {
			return ErrState
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer unlockFile(f)
	var p *policy
	if created {
		p, err = s.initial()
		// Marker is committed before policy; incomplete initialization fails closed.
		if err == nil {
			err = writePrivate(marker, []byte("1\n"))
		}
	} else {
		raw, e := ReadPrivate(marker)
		if e != nil || string(raw) != "1\n" {
			return ErrState
		}
		p, err = readPolicy(filepath.Join(dir, "policy.json"))
	}
	if err != nil {
		return ErrState
	}
	changed, result := fn(p)
	if changed || created {
		raw, e := json.Marshal(p)
		if e != nil || writePrivate(filepath.Join(dir, "policy.json"), raw) != nil {
			return ErrState
		}
	}
	return result
}
