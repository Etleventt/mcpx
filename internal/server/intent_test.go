package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/envelope"
	"mcpx/internal/mcpresult"
)

func TestRemoteRequestAllowsReadWithoutPurpose(t *testing.T) {
	runtime := newWorkspaceRuntime(t, "demo")
	request := mcpresult.Request(map[string]any{"workspace": "demo"})

	_, _, failure := runtime.remoteRequest(context.Background(), request)
	if failure != nil {
		t.Fatalf("read request should not require purpose: %+v", failure)
	}
}

func TestServerDerivesPurposeAndBoundsLegacyPurpose(t *testing.T) {
	derived := inferSemanticPurpose("command_run", envelope.Request{Payload: map[string]any{"command": "echo ok"}})
	if derived != "run command" {
		t.Fatalf("derived purpose=%q", derived)
	}
	legacy := strings.Repeat("x", 2048)
	bounded := inferSemanticPurpose("command_run", envelope.Request{Intent: legacy, Payload: map[string]any{"command": "echo ok"}})
	if bounded == "" || len(bounded) >= len(legacy) {
		t.Fatalf("legacy purpose was not sanitized/bounded: bytes=%d", len(bounded))
	}
}

func TestEveryRegisteredToolOmitsNarrativeIntentFields(t *testing.T) {
	runtime := newWorkspaceRuntime(t, "demo")
	protocol := mcp.NewServer(&mcp.Implementation{Name: "mcpx-test", Version: "0.1.0"}, nil)
	runtime.registerTools(protocol)
	for name, registered := range runtime.listedToolMap() {
		var schema struct {
			Properties map[string]any `json:"properties"`
		}
		if raw := mcpresult.ToolSchemaJSON(registered); len(raw) > 0 {
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatalf("tool %q schema: %v", name, err)
			}
		}
		for _, field := range []string{"purpose", "progress_summary"} {
			if schema.Properties[field] != nil {
				t.Errorf("tool %q exposes narrative field %q", name, field)
			}
		}
	}
}
