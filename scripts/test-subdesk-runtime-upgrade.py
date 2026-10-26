#!/usr/bin/env python3
"""Exercise old -> candidate -> old Runtime startup against an isolated MCPX_HOME.

Never reads or modifies the user's real MCPX account, binding, or state DB.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time


def unused_loopback_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def launch(binary, home, port):
    environment = dict(os.environ)
    environment.update(
        HOME=str(home.parent),
        MCPX_HOME=str(home),
        XDG_CONFIG_HOME=str(home.parent / ".config"),
        XDG_DATA_HOME=str(home.parent / ".local" / "share"),
        XDG_CACHE_HOME=str(home.parent / ".cache"),
        MCPX_LOG_LEVEL="error",
    )
    process = subprocess.Popen(
        [str(binary), "-addr", f"127.0.0.1:{port}"],
        cwd=str(home.parent),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.communicate(timeout=3)[1].decode(errors="replace")
            raise RuntimeError(f"{binary.name} exited before listen: {output[-1600:]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                time.sleep(0.2)
                if process.poll() is None:
                    return process
        except OSError:
            pass
        time.sleep(0.15)
    stop(process)
    raise RuntimeError(f"{binary.name} failed to listen on isolated port")


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        _, errors = process.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        _, errors = process.communicate(timeout=5)
    return errors.decode(errors="replace")[-1000:]


def schema(db):
    with sqlite3.connect(db) as connection:
        return {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old_runtime", type=Path)
    parser.add_argument("candidate_runtime", type=Path)
    args = parser.parse_args()
    old, candidate = args.old_runtime.resolve(strict=True), args.candidate_runtime.resolve(strict=True)
    if not os.access(old, os.X_OK) or not os.access(candidate, os.X_OK):
        parser.error("Both Runtime binaries must be executable")
    with tempfile.TemporaryDirectory(prefix="sd-upg-", dir="/private/tmp") as tmp:
        root = Path(tmp)
        home = root / ".mcpx"
        home.mkdir(mode=0o700)
        port = unused_loopback_port()
        config = f"""server:
  host: 127.0.0.1
  port: {port}
auth:
  mode: open
discovery:
  mcp:
    enabled: false
  skills:
    enabled: false
logging:
  enabled: false
"""
        (home / "config.yaml").write_text(config, encoding="utf-8")
        (home / "config.yaml").chmod(0o600)
        db = home / "state" / "mcpx.db"
        events = []
        for phase, binary in (("old", old), ("upgrade", candidate), ("rollback", old)):
            process = launch(binary, home, port)
            try:
                if not db.is_file():
                    raise RuntimeError(f"{phase}: Runtime database was not created")
                names = schema(db)
                has_blobs = "artifact_blobs" in names
                if phase == "upgrade" and not has_blobs:
                    raise RuntimeError("candidate did not apply screenshot blob migration")
                events.append({"phase": phase, "db_tables": len(names), "artifact_blobs": has_blobs})
            finally:
                errors = stop(process)
                if process.returncode not in (0, -15):
                    raise RuntimeError(f"{phase}: abnormal shutdown: {errors}")
        print(json.dumps({
            "status": "passed", "isolated_home": True,
            "production_runtime_untouched": True, "phases": events
        }, ensure_ascii=False))


if __name__ == "__main__":
    main()
