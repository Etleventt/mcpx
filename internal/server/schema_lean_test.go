package server

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/mcpresult"
)

func TestLeanSchemaMetrics(t *testing.T) {
	runtime := newWorkspaceRuntime(t, "demo")
	protocol := mcp.NewServer(&mcp.Implementation{Name: "schema-metrics", Version: "test"}, nil)
	runtime.registerTools(protocol)
	totalBytes := 0
	purposeSchemas := 0
	progressSchemas := 0
	for _, tool := range runtime.listedToolMap() {
		raw := string(mcpresult.ToolSchemaJSON(tool))
		totalBytes += len(raw)
		if strings.Contains(raw, `"purpose"`) {
			purposeSchemas++
		}
		if strings.Contains(raw, `"progress_summary"`) {
			progressSchemas++
		}
	}
	t.Logf("tools=%d schema_bytes=%d purpose_schemas=%d progress_schemas=%d", len(runtime.listedToolMap()), totalBytes, purposeSchemas, progressSchemas)
	if purposeSchemas != 0 || progressSchemas != 0 {
		t.Fatalf("public schemas still expose narrative fields: purpose=%d progress=%d", purposeSchemas, progressSchemas)
	}
	if totalBytes > 26<<10 {
		t.Fatalf("public schema budget regressed: bytes=%d budget=%d", totalBytes, 26<<10)
	}
}
