package source

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func scopeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{"wanted/a.go", "wanted/sub/b.go", "wantedish/c.go", "other/d.go", "wanted/vendor/hidden.go"} {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte("needle\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestScopedListFiltersBeforePolicyAndPreservesPaging(t *testing.T) {
	root := scopeFixture(t)
	checks := 0
	allowed := func(string) bool { checks++; return true }
	page, err := ListScoped(root, "**/*.go", "", []string{"wanted", "wanted/sub"}, "", 1, false, allowed)
	if err != nil || page.Total != 2 || len(page.Files) != 1 || checks != 2 || page.Files[0].Path != "wanted/a.go" {
		t.Fatalf("first page=%+v checks=%d err=%v", page, checks, err)
	}
	page, err = ListScoped(root, "**/*.go", "", []string{"wanted"}, page.NextCursor, 1, false, allowed)
	if err != nil || len(page.Files) != 1 || page.Files[0].Path != "wanted/sub/b.go" || page.NextCursor != "" {
		t.Fatalf("second page=%+v err=%v", page, err)
	}
	checks = 0
	page, err = ListWith(root, "wanted/**/*.go", "", "", 20, false, allowed)
	if err != nil || checks != 2 || page.Total != 2 {
		t.Fatalf("glob scope=%+v checks=%d err=%v", page, checks, err)
	}
	page, err = ListScoped(root, "", "wanted/sub/**", []string{"wanted"}, "", 20, false, allowed)
	if err != nil || len(page.Files) != 1 || page.Files[0].Path != "wanted/a.go" {
		t.Fatalf("recursive exclusion=%+v err=%v", page, err)
	}
}

func TestScopedSearchNeverFallsBackOutsideScope(t *testing.T) {
	root := scopeFixture(t)
	result, err := SearchWith(root, SearchOptions{Query: "needle", Paths: []string{"wanted"}, Limit: 1, CaseSensitive: true}, nil)
	if err != nil || len(result.Matches) != 1 || result.Matches[0].Path != "wanted/a.go" || !result.Truncated {
		t.Fatalf("search=%+v err=%v", result, err)
	}
	result, err = SearchWith(root, SearchOptions{Query: "needle", Paths: []string{"wanted"}, Limit: 1, Cursor: result.NextCursor, CaseSensitive: true}, nil)
	if err != nil || len(result.Matches) != 1 || result.Matches[0].Path != "wanted/sub/b.go" || result.Truncated {
		t.Fatalf("search continuation=%+v err=%v", result, err)
	}
	for _, scopes := range [][]string{{"missing"}, {"../outside"}, {root}, {""}} {
		result, err := SearchWith(root, SearchOptions{Query: "needle", Paths: scopes}, nil)
		if scopes[0] == "missing" {
			if err != nil || len(result.Matches) != 0 {
				t.Fatalf("missing scope=%+v err=%v", result, err)
			}
		} else if err == nil {
			t.Fatalf("invalid scope accepted: %q", scopes)
		}
	}
	page, err := ListScoped(root, "", "", []string{"wanted/a.go"}, "", 20, false, func(string) bool { return false })
	if err != nil || len(page.Files) != 0 {
		t.Fatalf("file policy bypass: %+v %v", page, err)
	}
}

func TestScopedWalkDoesNotFollowSymlinks(t *testing.T) {
	root := scopeFixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.go"), []byte("needle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	page, err := ListScoped(root, "", "", []string{"linked"}, "", 20, true, nil)
	if err != nil || len(page.Files) != 0 {
		t.Fatalf("symlink traversal: %+v err=%v", page, err)
	}
}

func TestScopedSmartQueryRespectsPaths(t *testing.T) {
	root := scopeFixture(t)
	result, err := SmartQueryPage(root, SmartQueryOptions{Query: "needle", Paths: []string{"wanted/a.go"}, Parallel: true, IncludeSHA256: true})
	if err != nil {
		t.Fatal(err)
	}
	files := result["files"].([]map[string]any)
	if len(files) != 1 || files[0]["path"] != "wanted/a.go" {
		t.Fatalf("context escaped scope: %+v", files)
	}
	serial, err := SmartQueryPage(root, SmartQueryOptions{Query: "needle", Paths: []string{"wanted/a.go"}, Parallel: false, IncludeSHA256: true})
	if err != nil || !reflect.DeepEqual(files, serial["files"]) {
		t.Fatalf("parallel changed results: %v", err)
	}
}

func TestCompiledGlobAndDirectoryPrefix(t *testing.T) {
	for _, pattern := range []string{"target/**/*.go", "**/*.go", "*.go", "target/[ab].go", "中文/**/*.go"} {
		match, err := CompileGlob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"target/a.go", "target/sub/b.go", "other/d.go", "a.go", "中文/a.go"} {
			want, err := MatchGlob(pattern, path)
			if err != nil || match(path) != want {
				t.Fatalf("pattern=%q path=%q", pattern, path)
			}
		}
	}
	if _, err := ListWith(t.TempDir(), "**/[", "", "", 20, false, nil); err == nil {
		t.Fatal("invalid glob accepted on empty tree")
	}
	if prefix := globDirectoryPrefix("target/sub/*.go"); prefix != "target/sub" {
		t.Fatalf("prefix=%q", prefix)
	}
	if fileInSearchScope("wantedish/a", []string{"wanted"}) || !fileInSearchScope("wanted/a", []string{"wanted"}) {
		t.Fatal("scope boundary mismatch")
	}
}
