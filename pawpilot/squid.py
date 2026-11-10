"""Talking to Squid: read the live allow list, apply a new one, read the access log."""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .domains import clean_host, is_hostname, same_entries
from .settings import Settings


@dataclass
class Result:
    ok: bool
    output: str


def live_acl(settings: Settings) -> str:
    try:
        with open(settings.squid_acl) as fh:
            return fh.read()
    except OSError:
        return ""


def apply(settings: Settings, acl: str) -> Result:
    """Write the staging file and run the privileged apply helper.

    The helper (deploy/pawpilot-apply) copies the staging file somewhere only
    root can write, checks every line is a plain domain entry, backs up the
    live list, installs the new one, has Squid parse its config and reloads
    it, putting the previous list back if either step fails.
    """
    tmp = settings.staging_path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(acl)
    os.chmod(tmp, 0o640)
    os.replace(tmp, settings.staging_path)
    try:
        proc = subprocess.run(shlex.split(settings.apply_cmd), capture_output=True, text=True, timeout=90)
    except FileNotFoundError as exc:
        return Result(False, f"Apply helper not found: {exc}")
    except subprocess.TimeoutExpired:
        return Result(False, "Apply helper timed out")
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        return Result(False, output or "Apply failed")
    if not same_entries(live_acl(settings), acl):
        # e.g. PAWPILOT_DATA_DIR or PAWPILOT_SQUID_ACL don't match the paths the helper uses.
        return Result(False, "The apply helper reported success, but the live allow list at "
                             f"{settings.squid_acl} doesn't match what was sent. Check that the data folder "
                             "and allow list paths in pawpilot.env match the ones in pawpilot-apply.")
    return Result(True, output or "Applied")


def service_state(settings: Settings) -> str:
    """systemd's view of Squid: active, inactive, failed, ... or unknown."""
    try:
        proc = subprocess.run(["systemctl", "is-active", settings.squid_service],
                              capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return proc.stdout.strip() or "unknown"


# ----- access log -------------------------------------------------------------

@dataclass
class LogSummary:
    readable: bool = False
    truncated: bool = False
    # host -> {"count": int, "last": float, "clients": set[str]} for denied requests
    denied: dict[str, dict] = field(default_factory=dict)
    # client ip -> {"requests": int, "denied": int, "last": float}
    clients: dict[str, dict] = field(default_factory=dict)


_cache: dict[str, tuple[tuple[int, int], LogSummary]] = {}


def stamp(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def read_log(settings: Settings) -> LogSummary:
    """Summarise the newest part of Squid's access log (native log format).

    The result is cached until the file changes, so busy pages don't re-read it.
    """
    path = settings.squid_log
    try:
        st = os.stat(path)
    except OSError:
        return LogSummary()
    key = (st.st_mtime_ns, st.st_size)
    cached = _cache.get(path)
    if cached and cached[0] == key:
        return cached[1]

    summary = LogSummary(readable=True)
    limit = max(1, settings.log_max_mb) * 1024 * 1024
    try:
        with open(path, "rb") as fh:
            if st.st_size > limit:
                fh.seek(st.st_size - limit)
                fh.readline()  # drop the partial first line
                summary.truncated = True
            for raw in fh:
                parts = raw.decode("utf-8", "replace").split()
                if len(parts) < 7:
                    continue
                try:
                    ts = float(parts[0])
                except ValueError:
                    continue
                ip, action, url = parts[2], parts[3], parts[6]
                denied = action.startswith("TCP_DENIED")
                client = summary.clients.setdefault(ip, {"requests": 0, "denied": 0, "last": 0.0})
                client["requests"] += 1
                client["last"] = max(client["last"], ts)
                if not denied:
                    continue
                client["denied"] += 1
                host = clean_host(url)
                if not is_hostname(host):
                    continue
                entry = summary.denied.setdefault(host, {"count": 0, "last": 0.0, "clients": set()})
                entry["count"] += 1
                entry["last"] = max(entry["last"], ts)
                entry["clients"].add(ip)
    except OSError:
        return LogSummary()
    _cache[path] = (key, summary)
    return summary
