package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"mcpx/internal/envelope"
	"mcpx/internal/observation"
	"mcpx/internal/terminal"
)

func TestObservationTargetPreservesValuesWithoutCancellation(t *testing.T) {
	type contextKey struct{}
	key := contextKey{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key, "authorization"), time.Hour)
	cancel()

	bridge := &observationBridge{
		resolve: func(ctx context.Context, request envelope.Request) (string, string) {
			if value := ctx.Value(key); value != "authorization" {
				t.Fatalf("context value=%v, want authorization", value)
			}
			if err := ctx.Err(); err != nil {
				t.Fatalf("resolution inherited cancellation: %v", err)
			}
			if _, ok := ctx.Deadline(); ok {
				t.Fatal("resolution inherited request deadline")
			}
			return "demo", request.RemoteSessionID
		},
	}

	workspace, remoteID := bridge.target(parent, envelope.Request{RemoteSessionID: "session-1"})
	if workspace != "demo" || remoteID != "session-1" {
		t.Fatalf("target=(%q, %q), want (demo, session-1)", workspace, remoteID)
	}
}

func TestPrepareTaskOutputBoundsCombinedTaskPayload(t *testing.T) {
	const limit = 128
	bridge := &observationBridge{maxTaskOutputBytes: limit}
	chunk := func(taskID, stream, value string, final bool) terminal.OutputChunk {
		return terminal.OutputChunk{
			TaskID:          taskID,
			RemoteSessionID: "session-1",
			Stream:          stream,
			Data:            []byte(value),
			Final:           final,
		}
	}

	var stored int64
	first, truncated, keep := bridge.prepareTaskOutput(chunk("task-1", "stdout", "first output", false), "first output")
	if !keep || truncated {
		t.Fatalf("first output keep=%v truncated=%v", keep, truncated)
	}
	stored += int64(len(first))

	second, truncated, keep := bridge.prepareTaskOutput(chunk("task-1", "stderr", "second output", false), "second output")
	if !keep || truncated {
		t.Fatalf("second output keep=%v truncated=%v", keep, truncated)
	}
	stored += int64(len(second))

	thirdText := strings.Repeat("x", 256)
	third, truncated, keep := bridge.prepareTaskOutput(chunk("task-1", "stdout", thirdText, false), thirdText)
	if !keep || !truncated {
		t.Fatalf("over-budget output keep=%v truncated=%v", keep, truncated)
	}
	stored += int64(len(third))
	if stored > limit {
		t.Fatalf("stored payload bytes=%d, want <= %d", stored, limit)
	}
	var payload map[string]any
	if err := json.Unmarshal(third, &payload); err != nil {
		t.Fatalf("truncated payload is invalid JSON: %v", err)
	}

	if _, _, keep := bridge.prepareTaskOutput(chunk("task-1", "stdout", "discarded", false), "discarded"); keep {
		t.Fatal("output after the first truncation was retained")
	}

	bridge.prepareTaskOutput(chunk("task-1", "stdout", "", true), "")
	bridge.prepareTaskOutput(chunk("task-1", "stderr", "", true), "")
	if len(bridge.outputBudget) != 0 {
		t.Fatalf("finished task output state remains: %+v", bridge.outputBudget)
	}
	if _, _, keep := bridge.prepareTaskOutput(chunk("task-2", "stdout", "independent", false), "independent"); !keep {
		t.Fatal("a different task inherited the first task's budget")
	}
}

func TestObserveTaskOutputPersistsOneTruncationEvent(t *testing.T) {
	var events []observation.Event
	recorder := observation.NewAsyncRecorder(16, func(_ context.Context, event observation.Event) error {
		events = append(events, event)
		return nil
	})
	bridge := &observationBridge{async: recorder, maxTaskOutputBytes: 128}
	rt := &Runtime{observation: bridge}
	chunk := func(taskID, stream, value string, final bool) terminal.OutputChunk {
		return terminal.OutputChunk{
			TaskID:          taskID,
			RemoteSessionID: "session-1",
			WorkspaceName:   "demo",
			Tool:            "command_execute",
			Stream:          stream,
			Data:            []byte(value),
			Final:           final,
		}
	}

	rt.observeTaskOutput(chunk("task-1", "stdout", "first output", false))
	rt.observeTaskOutput(chunk("task-1", "stderr", "second output", false))
	rt.observeTaskOutput(chunk("task-1", "stdout", strings.Repeat("x", 256), false))
	rt.observeTaskOutput(chunk("task-1", "stdout", "discarded", false))
	rt.observeTaskOutput(chunk("task-1", "stdout", "", true))
	rt.observeTaskOutput(chunk("task-1", "stderr", "", true))
	rt.observeTaskOutput(chunk("task-2", "stdout", "independent", false))
	recorder.Close(time.Second)

	if len(events) != 4 {
		t.Fatalf("persisted observation events=%d, want 4: %+v", len(events), events)
	}
	var taskOneBytes int
	var truncated int
	for _, event := range events {
		if event.Type != observation.TypeCommandOutput {
			t.Fatalf("unexpected event type=%+v", event)
		}
		if event.ExecutionTaskID == "task-1" {
			taskOneBytes += len(event.Output)
			if event.Truncated {
				truncated++
			}
		}
	}
	if taskOneBytes > 128 || truncated != 1 {
		t.Fatalf("task output bytes=%d truncated events=%d, want <=128 and 1", taskOneBytes, truncated)
	}
	if events[len(events)-1].ExecutionTaskID != "task-2" {
		t.Fatalf("new task output was not isolated: %+v", events)
	}
}
