package changeset

import (
	"fmt"
	"strings"
	"testing"
)

func performanceDiffFixture() ([]byte, []byte) {
	var text strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&text, "line %04d: stable source content for the benchmark\n", i)
	}
	before := text.String()
	after := strings.Replace(before, "line 0500: stable", "line 0500: changed", 1)
	return []byte(before), []byte(after)
}

func BenchmarkPerformanceSingleLineDiff(b *testing.B) {
	before, after := performanceDiffFixture()
	b.ReportAllocs()
	b.ResetTimer()
	bytes := 0
	for i := 0; i < b.N; i++ {
		bytes = len(diffFile("a/example.go", "b/example.go", before, after))
	}
	b.StopTimer()
	b.ReportMetric(float64(bytes), "diff-bytes/op")
}
