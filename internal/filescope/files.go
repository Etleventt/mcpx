package filescope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxFile = 1 << 20

func SHA(raw []byte) string { sum := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(sum[:]) }
func localPath(path string) bool {
	return path != "" && filepath.IsLocal(path) && !strings.ContainsRune(path, 0)
}
func Read(root *os.Root, path string) ([]byte, os.FileInfo, error) {
	if !localPath(path) {
		return nil, nil, ErrDenied
	}
	f, e := openRead(root, path)
	if e != nil {
		return nil, nil, ErrDenied
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !singleRegular(info) || info.Size() > MaxFile {
		return nil, nil, ErrDenied
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if e != nil || len(b) > MaxFile {
		return nil, nil, ErrDenied
	}
	return b, info, nil
}

type Entry struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Directory bool   `json:"directory"`
}
type Match struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// List and Search do not follow links during traversal. Every file is opened
// through the same root handle again, so a replaced parent cannot escape.
func Scan(root *os.Root, paths []string, query string, useRegex bool, limit int, allowed func(string) bool) (map[string]any, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	if len(paths) > 32 || len(query) > 2048 {
		return nil, ErrDenied
	}
	var re *regexp.Regexp
	var e error
	if useRegex {
		re, e = regexp.Compile(query)
		if e != nil {
			return nil, e
		}
	}
	entries := []Entry{}
	matches := []Match{}
	visited := 0
	budget := 8 * MaxFile
	truncated := false
	for _, base := range paths {
		if !localPath(base) {
			return nil, ErrDenied
		}
		walkErr := fs.WalkDir(root.FS(), filepath.ToSlash(base), func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if path != "." && allowed != nil && !allowed(path) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			visited++
			if visited > 20000 || len(entries) >= limit && query == "" || len(matches) >= limit || budget <= 0 {
				truncated = true
				return fs.SkipAll
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if query == "" {
				if path != "." {
					info, e := d.Info()
					if e == nil && (info.IsDir() || singleRegular(info)) {
						entries = append(entries, Entry{path, info.Size(), info.IsDir()})
					}
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			raw, _, e := Read(root, path)
			if e != nil {
				return nil
			}
			budget -= len(raw)
			if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
				return nil
			}
			for i, line := range strings.Split(string(raw), "\n") {
				ok := strings.Contains(line, query)
				if re != nil {
					ok = re.MatchString(line)
				}
				if ok {
					if len(line) > 2048 {
						line = line[:2048]
						for !utf8.ValidString(line) {
							line = line[:len(line)-1]
						}
					}
					matches = append(matches, Match{path, i + 1, line})
					if len(matches) >= limit {
						truncated = true
						return fs.SkipAll
					}
				}
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
			return nil, ErrDenied
		}
		if truncated {
			break
		}
	}
	if query != "" {
		return map[string]any{"matches": matches, "truncated": truncated}, nil
	}
	return map[string]any{"files": entries, "truncated": truncated}, nil
}

type Edit struct {
	Operation   string `json:"operation"`
	Path        string `json:"path"`
	BaseSHA256  string `json:"base_sha256"`
	Content     string `json:"content"`
	Match       string `json:"match"`
	Replacement string `json:"replacement"`
}

// EditOne deliberately omits arbitrary validators, formatters, batch journals,
// recursive deletion, and old snapshots: these are not file-only operations.
func EditOne(root *os.Root, op Edit) (map[string]any, error) {
	if !localPath(op.Path) || len(op.Content) > MaxFile || len(op.Replacement) > MaxFile {
		return nil, ErrDenied
	}
	var content []byte
	mode := os.FileMode(0600)
	switch op.Operation {
	case "create":
		if _, e := root.Lstat(op.Path); !errors.Is(e, os.ErrNotExist) {
			return nil, fmt.Errorf("file already exists or cannot be checked")
		}
		content = []byte(op.Content)
	case "replace_exact":
		old, info, e := Read(root, op.Path)
		if e != nil {
			return nil, e
		}
		if op.BaseSHA256 == "" || op.BaseSHA256 != SHA(old) {
			return nil, fmt.Errorf("file revision changed; read current sha256 first")
		}
		if op.Match == "" || strings.Count(string(old), op.Match) != 1 {
			return nil, fmt.Errorf("match must occur exactly once")
		}
		content = []byte(strings.Replace(string(old), op.Match, op.Replacement, 1))
		mode = info.Mode().Perm() & 0777
	default:
		return nil, fmt.Errorf("folder-only mode supports one create or replace_exact file operation; no executable hooks")
	}
	if len(content) > MaxFile {
		return nil, ErrDenied
	}
	parent := filepath.Dir(op.Path)
	if e := root.MkdirAll(parent, 0700); e != nil {
		return nil, ErrDenied
	}
	// Create is O_EXCL: another writer must not be overwritten. Replace uses an
	// atomic same-root rename; it never writes through a target symlink/hardlink.
	if op.Operation == "create" {
		f, e := root.OpenFile(op.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if e != nil {
			return nil, e
		}
		_, e = f.Write(content)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
	} else {
		id, e := randomID()
		if e != nil {
			return nil, e
		}
		tmp := filepath.Join(parent, ".subdesk-edit-"+id)
		f, e := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if e != nil {
			return nil, e
		}
		defer root.Remove(tmp)
		_, e = f.Write(content)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		current, _, e := Read(root, op.Path)
		if e != nil || SHA(current) != op.BaseSHA256 {
			return nil, fmt.Errorf("file changed while saving")
		}
		if e = root.Rename(tmp, op.Path); e != nil {
			return nil, e
		}
	}
	return map[string]any{"applied": true, "files_changed": 1, "path": op.Path, "sha256": SHA(content), "scope": "folders", "executed_commands": false}, nil
}
