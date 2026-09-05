#!/bin/sh
#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
printf '%s\n' '== MCPX versions =='
if [ -x "$HOME/.local/bin/mcpx-server-hardened" ]; then
  "$HOME/.local/bin/mcpx-server-hardened" -version
fi
if [ -x "$HOME/.local/bin/mcpx-agent-remote-gateway" ]; then
  "$HOME/.local/bin/mcpx-agent-remote-gateway" -version
fi

printf '%s\n' '== Runtime launchd =='
launchctl print "gui/$UID/com.mcpx.runtime" 2>/dev/null | grep -E 'state =|pid =|program =' || true

printf '%s\n' '== Agent processes =='
pgrep -ifl mcpx-agent || true

printf '%s\n' '== current legacy service =='
launchctl print "gui/$UID/com.mcpx.remote-agent-legacy" 2>/dev/null | grep -E 'state =|pid =|program =' || true

printf '%s\n' '== intentionally disabled redundant services =='
launchctl print-disabled "gui/$UID" 2>/dev/null | grep 'com.mcpx.remote-agent' || true

printf '%s\n' '== runtime data =='
du -sh "$HOME/.mcpx/state" "$HOME/.mcpx/tasks" "$HOME/.mcpx/logs" 2>/dev/null || true

df -h "$ROOT" | tail -n 1

printf '%s\n' '== relay lifecycle since current Agent start =='
LOG="$HOME/.local/state/mcpx-agent-legacy/agent.err.log"
if [ -f "$LOG" ]; then
  awk '/"msg":"mcpx-agent starting"/{buffer=""} {buffer=buffer $0 ORS} END{printf "%s", buffer}' "$LOG" | grep -E 'mcpx-agent starting|relay disconnected|agent connected' | tail -n 20 || true
fi
