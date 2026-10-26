package security

import (
	"testing"

	"mcpx/internal/config"
)

func TestLegacyAllowRegexCannotBypassReadonlyGitWhitelist(t *testing.T) {
	rules := config.DefaultConfig().Security.Commands
	for _, command := range []string{
		"git diff --output=write.txt",
		"git diff --ext-diff",
		"git status --output=write.txt",
		"git -C repo diff --output=write.txt",
		"git show --ext-diff HEAD",
	} {
		legacy := rules
		legacy.Allow = append(append([]string{}, rules.Allow...), `^git diff`, `^git status`)
		if got := MatchCommand(legacy, command); got != Confirm {
			t.Errorf("legacy %q: got %s, want confirm", command, got)
		}
		if got := MatchCommand(rules, command); got != Confirm {
			t.Errorf("default %q: got %s, want confirm", command, got)
		}
	}
	for _, command := range []string{"git diff --stat", "git status --short", "git -C repo status --porcelain"} {
		if got := MatchCommand(rules, command); got != Allow {
			t.Errorf("default safe %q: got %s, want allow", command, got)
		}
	}
}
