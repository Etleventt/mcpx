package changeset

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func TestDisplayDiffIsLocalAndRoundTrips(t *testing.T) {
	before, after := performanceDiffFixture()
	diff := diffFile("a/example.go", "b/example.go", before, after)
	if len(diff) > 2048 || !strings.Contains(diff, "+line 0500: changed") || strings.Contains(diff, "line 0000") {
		t.Fatalf("single-line change was not local: bytes=%d", len(diff))
	}
	got, err := applyUnifiedPatch(before, diff)
	if err != nil || !bytes.Equal(got, after) {
		t.Fatalf("round trip failed: %v", err)
	}
	after = bytes.Replace(after, []byte("line 0900: stable"), []byte("line 0900: second"), 1)
	diff = diffFile("a/example.go", "b/example.go", before, after)
	if strings.Count(diff, "@@ -") != 2 || len(diff) > 3000 {
		t.Fatalf("distant changes were not separated: bytes=%d", len(diff))
	}
	got, err = applyUnifiedPatch(before, diff)
	if err != nil || !bytes.Equal(got, after) {
		t.Fatalf("multi-hunk round trip failed: %v", err)
	}
}

func TestDisplayDiffEdgeCases(t *testing.T) {
	cases := [][2]string{
		{"", "hello\n"}, {"hello\n", ""}, {"", "hello"}, {"hello", "hello\n"},
		{"hello\n", "hello"}, {"a\nb\nc\n", "a\ninsert\nb\nc\n"},
		{"a\nb\nc", "a\nb\n"}, {"one\r\ntwo\r\n", "one\r\nchanged\r\n"},
		{"重复\n重复\n末尾", "重复\n插入\n重复\n末尾"},
		{strings.Repeat("old\n", 300), strings.Repeat("new\n", 300)},
	}
	for _, pair := range cases {
		diff := diffFile("a/f", "b/f", []byte(pair[0]), []byte(pair[1]))
		got, err := applyUnifiedPatch([]byte(pair[0]), diff)
		if err != nil || string(got) != pair[1] {
			t.Fatalf("edge round trip: err=%v before=%q after=%q diff=%q got=%q", err, pair[0], pair[1], diff, got)
		}
	}
	if diffFile("a/f", "b/f", []byte("same\n"), []byte("same\n")) != "" {
		t.Fatal("unchanged content emitted a diff")
	}
	if !strings.Contains(diffFile("a/f", "b/g", []byte("same"), []byte("same")), "+++ b/g") {
		t.Fatal("rename headers missing")
	}
}

func TestDisplayDiffRandomRoundTrips(t *testing.T) {
	rng := rand.New(rand.NewSource(20260905))
	makeText := func() string {
		var out strings.Builder
		for n := rng.Intn(50); n > 0; n-- {
			out.WriteString([]string{"alpha", "beta", "", "中文", "same"}[rng.Intn(5)])
			out.WriteByte('\n')
		}
		text := out.String()
		if rng.Intn(2) == 0 {
			text = strings.TrimSuffix(text, "\n")
		}
		return text
	}
	for i := 0; i < 500; i++ {
		before, after := makeText(), makeText()
		if before == after {
			continue
		}
		diff := diffFile("a/f", "b/f", []byte(before), []byte(after))
		got, err := applyUnifiedPatch([]byte(before), diff)
		if err != nil || string(got) != after {
			t.Fatalf("case %d: err=%v before=%q after=%q diff=%q got=%q", i, err, before, after, diff, got)
		}
	}
}

func TestDisplayFileChangesPreservesJournal(t *testing.T) {
	files := []FileChange{
		{Ordinal: 0, Operation: "update", Path: "f", Original: []byte("old\n"), Proposed: []byte("middle\n"), OriginalSHA256: "old", ProposedSHA256: "middle", ExpectedSHA256: "old"},
		{Ordinal: 1, Operation: "update", Path: "f", Original: []byte("middle\n"), Proposed: []byte("new\n"), OriginalSHA256: "middle", ProposedSHA256: "new", ExpectedSHA256: "old"},
	}
	digest := digestFiles(files)
	display := DisplayFileChanges(files)
	if len(display) != 1 || string(display[0].Original) != "old\n" || string(display[0].Proposed) != "new\n" {
		t.Fatalf("bad display chain: %+v", display)
	}
	if digestFiles(files) != digest || string(files[0].Proposed) != "middle\n" || len(files) != 2 {
		t.Fatal("display changed transaction or digest")
	}
	diff := unifiedDiff(files)
	if strings.Count(diff, "--- a/f") != 1 || strings.Contains(diff, "middle") {
		t.Fatalf("intermediate diff leaked: %s", diff)
	}
}
