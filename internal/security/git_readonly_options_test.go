package security

import (
	"testing"

	"mcpx/internal/config"
)

func TestReadonlyGitOptionsCannotWriteOrExecute(t *testing.T) {
	rules := config.CommandRules{}
	for _, command := range []string{
		"git diff --output=leak.txt",
		"git diff --ext-diff",
		"git show --ext-diff HEAD",
		"git log --format=%x00 --output=out",
		"git status --output=out",
		"git -C project diff -o out.txt",
		"git diff --textconv",
		"git show --pretty=raw",
		"git log --exec=sh",
	} {
		if got := MatchCommand(rules, command); got != Confirm {
			t.Errorf("%q: got %s, want confirm", command, got)
		}
	}
	for _, command := range []string{
		"git status --porcelain=v1 --branch",
		"git -C sub status --short",
		"git diff --no-ext-diff --name-only HEAD",
		"git diff -U3 --stat",
		"git show HEAD",
		"git log --oneline -n10",
	} {
		if got := MatchCommand(rules, command); got != Allow {
			t.Errorf("%q: got %s, want allow", command, got)
		}
	}
}
