#!/usr/bin/env python3
"""Read-only upstream audit for the web-mac MCPX fork.

Never merges, checks out, commits, pushes, or modifies the repository.
Uses GitHub's public API and optional GITHUB_TOKEN for rate limits.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_REPO = "opentokenz/mcpx"
ADOPTIONS = ROOT / "docs" / "upstream-adoptions.json"


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def get_json(url: str):
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "mcpx-web-mac-audit"})
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def category(subject: str) -> tuple[str, str]:
    text = subject.lower()
    if subject.startswith("Merge "):
        return "merge", "usually-skip"
    if any(word in text for word in ("windows", "win32", "desktop", "tray", "gui", "托盘", "图形")):
        return "platform-ui", "usually-skip"
    if any(word in text for word in ("security", "auth", "oauth", "secret", "credential", "权限", "安全", "鉴权")):
        return "security", "review-now"
    if subject.startswith("fix") or any(word in text for word in ("retention", "reconnect", "session", "daemon", "观测", "确认", "恢复", "泄漏", "增长")):
        return "reliability", "review-now"
    if any(word in text for word in ("protocol", "mcp", "arc", "execute", "tool", "协议")):
        return "protocol", "compat-review"
    return "other", "review-later"


def load_adoptions() -> dict[str, dict]:
    if not ADOPTIONS.exists():
        return {}
    data = json.loads(ADOPTIONS.read_text())
    return {entry["sha"]: entry for entry in data.get("commits", [])}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--base", default="", help="upstream commit to compare; default current HEAD")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    base = args.base or git("rev-parse", "HEAD")
    api = "https://api.github.com/repos/" + args.repo
    encoded_base = urllib.parse.quote(base, safe="")
    try:
        release = get_json(api + "/releases/latest")
        comparison = get_json(api + "/compare/" + encoded_base + "...main")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        print(f"upstream audit failed: {exc}", file=sys.stderr)
        return 2
    adopted = load_adoptions()
    commits = []
    counts: dict[str, int] = {}
    for item in comparison.get("commits", []):
        sha = item.get("sha", "")
        subject = item.get("commit", {}).get("message", "").splitlines()[0]
        group, recommendation = category(subject)
        counts[group] = counts.get(group, 0) + 1
        adoption = adopted.get(sha)
        commits.append({
            "sha": sha,
            "date": item.get("commit", {}).get("committer", {}).get("date", ""),
            "subject": subject,
            "category": group,
            "recommendation": "adopted" if adoption else recommendation,
            "adoption": adoption,
        })
    result = {
        "repository": args.repo,
        "local_head": git("rev-parse", "HEAD"),
        "compare_base": base,
        "latest_release": {"tag": release.get("tag_name"), "published_at": release.get("published_at")},
        "comparison": {
            "status": comparison.get("status"),
            "ahead_by": comparison.get("ahead_by"),
            "behind_by": comparison.get("behind_by"),
            "total_commits": comparison.get("total_commits"),
            "changed_files": len(comparison.get("files", [])),
        },
        "category_counts": counts,
        "commits": commits,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print(f"upstream {args.repo}: latest={result['latest_release']['tag']} base={base[:12]} ahead={result['comparison']['ahead_by']} files={result['comparison']['changed_files']}")
    for item in commits:
        if item["recommendation"] == "usually-skip":
            continue
        suffix = ""
        if item["adoption"]:
            suffix = " (" + item["adoption"].get("status", "adopted") + ")"
        print(f"{item['recommendation']:13} {item['category']:11} {item['sha'][:10]} {item['subject']}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
