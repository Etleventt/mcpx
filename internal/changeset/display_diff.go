package changeset

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
)

// DisplayFileChanges collapses content-edit chains for presentation only.
// Apply, digest validation, persistence and rollback must use the original Files.
func DisplayFileChanges(files []FileChange) []FileChange {
	result := make([]FileChange, 0, len(files))
	byPath := make(map[string]int)
	for _, item := range files {
		if index, ok := byPath[item.Path]; ok && item.Operation == "update" {
			previous := &result[index]
			if (previous.Operation == "update" || previous.Operation == "create") &&
				previous.ProposedSHA256 == item.OriginalSHA256 && bytes.Equal(previous.Proposed, item.Original) {
				previous.Proposed = item.Proposed
				previous.ProposedSHA256 = item.ProposedSHA256
				enrichFileChangeFormat(previous)
				continue
			}
		}
		byPath[item.Path] = len(result)
		result = append(result, item)
	}
	return result
}

type displayDiffLine struct {
	kind byte
	text string
}

func compactDiffFile(oldPath, newPath string, before, after []byte) string {
	if bytes.Equal(before, after) {
		if strings.TrimPrefix(oldPath, "a/") == strings.TrimPrefix(newPath, "b/") {
			return ""
		}
		return fmt.Sprintf("--- %s\n+++ %s\n", oldPath, newPath)
	}
	a, b := displayDiffLines(string(before)), displayDiffLines(string(after))
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	lines := make([]displayDiffLine, 0, len(a)+len(b))
	for _, text := range a[:prefix] {
		lines = append(lines, displayDiffLine{' ', text})
	}
	left, right := a[prefix:len(a)-suffix], b[prefix:len(b)-suffix]
	middle, ok := boundedLineDiff(left, right)
	if ok {
		lines = append(lines, middle...)
	} else {
		// Large rewrites fall back to a valid replacement, not quadratic work.
		for _, text := range left {
			lines = append(lines, displayDiffLine{'-', text})
		}
		for _, text := range right {
			lines = append(lines, displayDiffLine{'+', text})
		}
	}
	for _, text := range a[len(a)-suffix:] {
		lines = append(lines, displayDiffLine{' ', text})
	}
	return renderDisplayDiff(oldPath, newPath, lines)
}

func displayDiffLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// boundedLineDiff uses Myers' shortest edit path with explicit CPU and memory
// bounds. Common prefixes/suffixes are handled by the caller before this search.
func boundedLineDiff(a, b []string) ([]displayDiffLine, bool) {
	if len(a) == 0 || len(b) == 0 {
		return nil, false
	}
	maxDistance := min(len(a)+len(b), 128)
	offset := maxDistance + 1
	v := make([]int, 2*maxDistance+3)
	trace := make([][]int, 0, maxDistance+1)
	work := 0
	for d := 0; d <= maxDistance; d++ {
		trace = append(trace, slices.Clone(v))
		for k := -d; k <= d; k += 2 {
			x := 0
			if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
				x = v[offset+k+1]
			} else {
				x = v[offset+k-1] + 1
			}
			y := x - k
			for x < len(a) && y < len(b) && a[x] == b[y] {
				x++
				y++
				work++
				if work > 2_000_000 {
					return nil, false
				}
			}
			v[offset+k] = x
			if x >= len(a) && y >= len(b) {
				return backtrackLineDiff(a, b, trace, offset), true
			}
		}
	}
	return nil, false
}

func backtrackLineDiff(a, b []string, trace [][]int, offset int) []displayDiffLine {
	x, y := len(a), len(b)
	result := make([]displayDiffLine, 0, x+y)
	for d := len(trace) - 1; d >= 0; d-- {
		v := trace[d]
		k := x - y
		previousK := k - 1
		if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
			previousK = k + 1
		}
		previousX := v[offset+previousK]
		previousY := previousX - previousK
		for x > previousX && y > previousY {
			x--
			y--
			result = append(result, displayDiffLine{' ', a[x]})
		}
		if d == 0 {
			break
		}
		if x == previousX {
			y--
			result = append(result, displayDiffLine{'+', b[y]})
		} else {
			x--
			result = append(result, displayDiffLine{'-', a[x]})
		}
	}
	slices.Reverse(result)
	return result
}

func renderDisplayDiff(oldPath, newPath string, lines []displayDiffLine) string {
	const contextLines = 3
	type span struct{ start, end int }
	var hunks []span
	for i, line := range lines {
		if line.kind == ' ' {
			continue
		}
		next := span{max(0, i-contextLines), min(len(lines), i+contextLines+1)}
		if len(hunks) > 0 && next.start <= hunks[len(hunks)-1].end {
			hunks[len(hunks)-1].end = next.end
		} else {
			hunks = append(hunks, next)
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", oldPath, newPath)
	cursor, oldBefore, newBefore := 0, 0, 0
	for _, hunk := range hunks {
		for cursor < hunk.start {
			if lines[cursor].kind != '+' {
				oldBefore++
			}
			if lines[cursor].kind != '-' {
				newBefore++
			}
			cursor++
		}
		oldCount, newCount := 0, 0
		for _, line := range lines[hunk.start:hunk.end] {
			if line.kind != '+' {
				oldCount++
			}
			if line.kind != '-' {
				newCount++
			}
		}
		oldStart, newStart := oldBefore, newBefore
		if oldCount > 0 {
			oldStart++
		}
		if newCount > 0 {
			newStart++
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
		for _, line := range lines[hunk.start:hunk.end] {
			out.WriteByte(line.kind)
			out.WriteString(line.text)
			if !strings.HasSuffix(line.text, "\n") {
				out.WriteString("\n\\ No newline at end of file\n")
			}
		}
		cursor = hunk.end
		oldBefore += oldCount
		newBefore += newCount
	}
	return out.String()
}
