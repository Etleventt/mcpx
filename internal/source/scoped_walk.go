package source

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// pathsScoped walks from the workspace root so symlinked directories are never
// followed. Unrelated subtrees are pruned before reading their directory entries.
// Returned paths and cursor ordering remain workspace-relative and deterministic.
func pathsScoped(root, pattern, excludePattern string, scopes []string, allowed func(string) bool) ([]string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	scopes, err = normalizeSearchPaths(scopes)
	if err != nil {
		return nil, err
	}
	include, err := CompileGlob(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}
	exclude, err := CompileGlob(excludePattern)
	if err != nil {
		return nil, fmt.Errorf("invalid exclude pattern: %w", err)
	}
	prefix := globDirectoryPrefix(pattern)
	var result []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if ignoredDirectories[entry.Name()] || !directoryInSearchScope(relative, scopes) ||
				(prefix != "" && !pathsOverlap(relative, prefix)) {
				return fs.SkipDir
			}
			// Only a recursive terminal ** proves that every descendant is excluded.
			if strings.HasSuffix(filepath.ToSlash(excludePattern), "/**") && exclude(relative+"/") {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || !fileInSearchScope(relative, scopes) {
			return nil
		}
		if (pattern != "" && !include(relative)) || (excludePattern != "" && exclude(relative)) {
			return nil
		}
		// Authorization is still checked for every returned file, after cheap filters.
		if allowed != nil && !allowed(relative) {
			return nil
		}
		result = append(result, relative)
		return nil
	})
	sort.Strings(result)
	return result, err
}

func normalizeSearchPaths(paths []string) ([]string, error) {
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		clean := filepath.ToSlash(filepath.Clean(path))
		if path == "" || filepath.IsAbs(path) || filepath.VolumeName(path) != "" ||
			clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("paths must be workspace-relative: %q", path)
		}
		result = append(result, clean)
	}
	return result, nil
}

func fileInSearchScope(path string, scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, scope := range scopes {
		if scope == "." || path == scope || strings.HasPrefix(path, scope+"/") {
			return true
		}
	}
	return false
}

func directoryInSearchScope(path string, scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, scope := range scopes {
		if scope == "." || pathsOverlap(path, scope) {
			return true
		}
	}
	return false
}

func pathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func globDirectoryPrefix(pattern string) string {
	pattern = filepath.ToSlash(pattern)
	if wildcard := strings.IndexAny(pattern, "*?[\\"); wildcard >= 0 {
		pattern = pattern[:wildcard]
	}
	if slash := strings.LastIndexByte(pattern, '/'); slash >= 0 {
		return pattern[:slash]
	}
	return ""
}
