package server

import (
	"encoding/json"
	"strings"
	"testing"

	"mcpx/internal/terminal"
)

func decodeTaskOutputText(t *testing.T, encoded []byte) string {
	t.Helper()
	var payload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Text
}

func TestPrepareTaskOutputBoundsCombinedStreamsAndCleansState(t *testing.T) {
	bridge := &observationBridge{maxTaskOutputBytes: 220}
	base := terminal.OutputChunk{TaskID: "task", RemoteSessionID: "session", Stream: "stdout", Data: []byte("first")}
	first, truncated, keep := bridge.prepareTaskOutput(base, strings.Repeat("a", 45))
	if !keep || truncated || len(first) == 0 {
		t.Fatalf("first keep=%v truncated=%v bytes=%d", keep, truncated, len(first))
	}
	secondChunk := base
	secondChunk.Stream = "stderr"
	secondChunk.Data = []byte("second")
	second, truncated, keep := bridge.prepareTaskOutput(secondChunk, strings.Repeat("界", 80))
	if !keep || !truncated || len(first)+len(second) > int(bridge.maxTaskOutputBytes) {
		t.Fatalf("second keep=%v truncated=%v total=%d", keep, truncated, len(first)+len(second))
	}
	if text := decodeTaskOutputText(t, second); !strings.Contains(text, observationTaskOutputMarker) {
		t.Fatalf("truncation marker missing: %q", text)
	}
	third := base
	third.Data = []byte("ignored")
	if encoded, truncated, keep := bridge.prepareTaskOutput(third, "ignored"); keep || truncated || len(encoded) != 0 {
		t.Fatalf("post-truncation chunk persisted: keep=%v truncated=%v bytes=%d", keep, truncated, len(encoded))
	}
	stdoutFinal := base
	stdoutFinal.Data = nil
	stdoutFinal.Final = true
	_, _, _ = bridge.prepareTaskOutput(stdoutFinal, "")
	stderrFinal := stdoutFinal
	stderrFinal.Stream = "stderr"
	_, _, _ = bridge.prepareTaskOutput(stderrFinal, "")
	if len(bridge.outputBudget) != 0 {
		t.Fatalf("budget state leaked after final streams: %+v", bridge.outputBudget)
	}
}

func TestPrepareTaskOutputBudgetsTasksIndependently(t *testing.T) {
	bridge := &observationBridge{maxTaskOutputBytes: 120}
	for _, taskID := range []string{"one", "two"} {
		encoded, truncated, keep := bridge.prepareTaskOutput(terminal.OutputChunk{TaskID: taskID, RemoteSessionID: "session", Stream: "stdout", Data: []byte("x")}, strings.Repeat(taskID, 40))
		if !keep || !truncated || len(encoded) > int(bridge.maxTaskOutputBytes) {
			t.Fatalf("task %s keep=%v truncated=%v bytes=%d", taskID, keep, truncated, len(encoded))
		}
	}
	if len(bridge.outputBudget) != 2 {
		t.Fatalf("task budgets were not isolated: %+v", bridge.outputBudget)
	}
}

func TestFitTaskOutputPayloadNeverSplitsUTF8(t *testing.T) {
	for budget := int64(1); budget <= 256; budget++ {
		encoded := fitTaskOutputPayload(strings.Repeat("🙂中文", 20), 123, budget)
		if int64(len(encoded)) > budget {
			t.Fatalf("budget=%d produced %d bytes", budget, len(encoded))
		}
		if len(encoded) > 0 {
			_ = decodeTaskOutputText(t, encoded)
		}
	}
}
