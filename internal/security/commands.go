package security

import (
	"regexp"
	"strings"

	"mcpx/internal/config"
)

// Decision is the outcome of command policy matching.
type Decision int

const (
	// Allow executes without human confirmation.
	Allow Decision = iota
	// Confirm requires explicit user semantic confirmation before execute.
	Confirm
	// Deny rejects the command.
	Deny
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Confirm:
		return "confirm"
	case Deny:
		return "deny"
	default:
		return "unknown"
	}
}

// ParseDefault maps config string to Decision. Unknown/empty => Confirm (safe built-in).
func ParseDefault(s string) Decision {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return Allow
	case "deny":
		return Deny
	case "confirm", "":
		return Confirm
	default:
		return Confirm
	}
}

// MatchCommand decides whether a command is allowed, needs confirmation, or must
// be rejected. deny/allow rules match whole commands or individual && / ;
// segments; pipes, redirections, background operators, and command substitution
// are structurally rejected because they cannot be split safely.
func MatchCommand(rules config.CommandRules, command string) Decision {
	return MatchCommandWithTrust(rules, command, false)
}

// MatchCommandWithTrust keeps deny rules authoritative while trusted sessions
// automatically approve every confirmation decision.
func MatchCommandWithTrust(rules config.CommandRules, command string, trusted bool) Decision {
	if containsUnsafeOperator(command) {
		return Deny
	}
	needsConfirmation := false
	for _, segment := range splitSegments(command) {
		switch matchSegment(rules, segment, trusted) {
		case Deny:
			return Deny
		case Confirm:
			needsConfirmation = true
		}
	}
	if needsConfirmation {
		return Confirm
	}
	return Allow
}

// matchSegment evaluates a single command segment without control operators.
func matchSegment(rules config.CommandRules, segment string, trusted bool) Decision {
	if matchAny(rules.Deny, segment) {
		return Deny
	}
	if matchAny(rules.Confirm, segment) {
		if trusted {
			return Allow
		}
		return Confirm
	}
	if matchAny(rules.Allow, segment) {
		// Previously persisted configs allow broad "^git diff"/"^git status"
		// rules. Such prefixes must not bypass the Git read-only whitelist.
		if isGitInspectionSegment(segment) && !isReadonlySegment(segment) {
			if trusted {
				return Allow
			}
			return Confirm
		}
		return Allow
	}
	if autoAllowReadonlyEnabled(rules) && isReadonlyCommand(segment) {
		return Allow
	}
	decision := ParseDefault(rules.Default)
	if trusted && decision == Confirm {
		return Allow
	}
	return decision
}

// containsUnsafeOperator reports shell syntax that cannot be split into
// independently judged segments: pipes, redirections, background operators,
// newlines, and command substitution. The && sequence is consumed first so a
// bare & (background) still triggers rejection.
func containsUnsafeOperator(command string) bool {
	withoutAnd := strings.ReplaceAll(command, "&&", "")
	return strings.ContainsAny(command, "|<>`\n") ||
		strings.Contains(command, "$(") ||
		strings.Contains(withoutAnd, "&")
}

// splitSegments splits a command on && and ; so every segment is judged
// independently. Segments containing an unsafe operator are already rejected
// by containsUnsafeOperator before this point.
func splitSegments(command string) []string {
	var segments []string
	for _, andPart := range strings.Split(command, "&&") {
		for _, semiPart := range strings.Split(andPart, ";") {
			segments = append(segments, strings.TrimSpace(semiPart))
		}
	}
	return segments
}

func autoAllowReadonlyEnabled(rules config.CommandRules) bool {
	return rules.AutoAllowReadonly == nil || *rules.AutoAllowReadonly
}

// isReadonlyCommand reports whether every && / ; segment of the command is
// read-only. A single non-read-only segment falls back to normal policy.
func isReadonlyCommand(command string) bool {
	for _, segment := range strings.Split(command, "&&") {
		for _, part := range strings.Split(segment, ";") {
			if !isReadonlySegment(part) {
				return false
			}
		}
	}
	return true
}

// isReadonlySegment accepts only commands with no side effects and no shell
// metacharacters (pipe, redirect, background, command substitution). Arguments
// that can be expanded by the shell are rejected because this matcher does not
// resolve them against the workspace before execution.
func isReadonlySegment(segment string) bool {
	trimmed := strings.TrimSpace(segment)
	if trimmed == "" {
		return false
	}
	if strings.ContainsAny(trimmed, "|&><`\n") || strings.Contains(trimmed, "$(") {
		return false
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "ls":
		return allReadonlyArguments(fields[1:])
	case "pwd":
		return len(fields) == 1
	case "cat", "head", "tail":
		return allReadonlyArguments(fields[1:])
	case "git":
		return isReadonlyGit(fields[1:])
	}
	return false
}

// isGitInspectionSegment recognizes the Git subcommands historically covered
// by broad allow patterns, including one or more -C workspace prefixes.
func isGitInspectionSegment(segment string) bool {
	args := strings.Fields(strings.TrimSpace(segment))
	if len(args) < 2 || args[0] != "git" {
		return false
	}
	args = args[1:]
	for len(args) > 0 && args[0] == "-C" {
		if len(args) < 2 {
			return false
		}
		args = args[2:]
	}
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "status", "diff", "log", "show":
		return true
	}
	return false
}

// isReadonlyGit only auto-approves known non-writing Git options. Generic
// argument character checks are insufficient: e.g. git diff --output=path
// writes to disk, and --ext-diff may execute an external program.
func isReadonlyGit(args []string) bool {
	for len(args) > 0 && args[0] == "-C" {
		if len(args) < 2 || !safeReadonlyArgument(args[1]) || strings.HasPrefix(args[1], "-") {
			return false
		}
		args = args[2:]
	}
	if len(args) == 0 {
		return false
	}
	command := args[0]
	switch command {
	case "status", "diff", "log", "show":
	default:
		return false
	}
	paths := false
	for _, arg := range args[1:] {
		if !safeReadonlyArgument(arg) {
			return false
		}
		if arg == "--" {
			paths = true
			continue
		}
		if paths || !strings.HasPrefix(arg, "-") {
			continue
		}
		if !safeReadonlyGitOption(command, arg) {
			return false
		}
	}
	return true
}

func safeReadonlyGitOption(command, arg string) bool {
	// Reject all unknown options, especially --output, --ext-diff,
	// --textconv and pager/config/exec hooks.
	switch command {
	case "status":
		switch arg {
		case "-s", "-b", "-sb", "--short", "--branch", "--porcelain",
			"--porcelain=v1", "--porcelain=v2", "--ignored", "--show-stash",
			"--ahead-behind", "--no-ahead-behind", "--renames", "--no-renames",
			"-uno", "--untracked-files=all", "--untracked-files=normal",
			"--untracked-files=no":
			return true
		}
	case "diff", "log", "show":
		switch arg {
		case "--stat", "--shortstat", "--numstat", "--name-only", "--name-status",
			"--check", "--no-color", "--color=never", "--no-ext-diff",
			"--no-textconv", "--oneline", "--no-renames", "--raw":
			return true
		}
		if command == "diff" && (arg == "--cached" || arg == "--staged" ||
			arg == "-w" || arg == "--ignore-space-at-eol") {
			return true
		}
		if (command == "log" || command == "show") &&
			(arg == "--pretty=oneline" || arg == "--format=oneline" ||
				arg == "--pretty=short" || arg == "--format=short" ||
				arg == "--decorate" || arg == "--no-decorate") {
			return true
		}
		if strings.HasPrefix(arg, "-U") && len(arg) > 2 {
			return allDigits(arg[2:])
		}
		if strings.HasPrefix(arg, "--unified=") {
			return allDigits(strings.TrimPrefix(arg, "--unified="))
		}
		if (command == "log" || command == "show") && strings.HasPrefix(arg, "-n") {
			return allDigits(strings.TrimPrefix(arg, "-n"))
		}
		if (command == "log" || command == "show") && strings.HasPrefix(arg, "--max-count=") {
			return allDigits(strings.TrimPrefix(arg, "--max-count="))
		}
	}
	return false
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func allReadonlyArguments(args []string) bool {
	for _, arg := range args {
		if !safeReadonlyArgument(arg) {
			return false
		}
	}
	return true
}

func safeReadonlyArgument(arg string) bool {
	if arg == "" || strings.HasPrefix(arg, "/") || strings.Contains(arg, "..") {
		return false
	}
	// These characters trigger shell expansion or make the path differ from
	// the literal value reviewed by the policy matcher.
	return !strings.ContainsAny(arg, "$~{}\\*?[]'\"")
}

func matchAny(patterns []string, command string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(command) {
			return true
		}
	}
	return false
}

// MatchFile applies file path policy. Once any list is configured, unmatched
// paths require confirmation, making an allow list behave as a real whitelist.
func MatchFile(rules config.FileRules, path string) Decision {
	return MatchFileWithTrust(rules, path, false)
}

// MatchFileWithTrust keeps deny rules authoritative while trusted sessions
// automatically approve both explicit and fallback file confirmations.
func MatchFileWithTrust(rules config.FileRules, path string, trusted bool) Decision {
	if matchAny(rules.Deny, path) {
		return Deny
	}
	if matchAny(rules.Confirm, path) {
		if trusted {
			return Allow
		}
		return Confirm
	}
	if matchAny(rules.Allow, path) {
		return Allow
	}
	if len(rules.Allow)+len(rules.Confirm)+len(rules.Deny) > 0 {
		if trusted {
			return Allow
		}
		return Confirm
	}
	return Allow
}
