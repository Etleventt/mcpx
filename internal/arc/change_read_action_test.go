package arc

import "testing"

func TestReadOnlyChangeContinuationDoesNotRequestConfirmation(t *testing.T) {
	for _, tool := range []string{"change_read", "change_diff", "change_history", "source_read"} {
		actions := actionsFrom(map[string]any{"next_action": map[string]any{
			"tool": tool, "arguments": map[string]any{"view": "diff", "offset": 64},
		}})
		if len(actions) != 1 || actions[0].Confirm || actions[0].Type != "continue" {
			t.Fatalf("read-only continuation %q: %+v", tool, actions)
		}
		if actions[0].Arguments["offset"] != 64 {
			t.Fatal("continuation offset changed")
		}
	}
}

func TestMutationChangeContinuationStillRequestsConfirmation(t *testing.T) {
	for _, tool := range []string{"change", "change_execute", "change_prepare"} {
		actions := actionsFrom(map[string]any{"next_action": map[string]any{
			"tool": tool, "arguments": map[string]any{"action": "apply"},
		}})
		if len(actions) != 1 || !actions[0].Confirm || actions[0].Type != "mutation" {
			t.Fatalf("mutation continuation %q: %+v", tool, actions)
		}
	}
}
