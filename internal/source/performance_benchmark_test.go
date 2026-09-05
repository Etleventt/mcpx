package source

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkPerformanceScopedList(b *testing.B) {
	root := b.TempDir()
	for project := 0; project < 40; project++ {
		dir := filepath.Join(root, fmt.Sprintf("project-%02d", project), "src")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatal(err)
		}
		for index := 0; index < 100; index++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%03d.go", index)), []byte("package fixture\n"), 0o600); err != nil {
				b.Fatal(err)
			}
		}
	}
	checks := 0
	allowed := func(string) bool { checks++; return true }
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := ListWith(root, "project-20/**/*.go", "", "", 20, false, allowed)
		if err != nil || len(result.Files) != 20 || result.Total != 100 {
			b.Fatalf("list: files=%d total=%d err=%v", len(result.Files), result.Total, err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(checks)/float64(b.N), "policy-checks/op")
}
