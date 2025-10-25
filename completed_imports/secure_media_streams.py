#!/usr/bin/env python3
"""
secure_media_streams.py

Audit and optionally terminate outbound audio/video streaming processes and
harden the host by disabling related user‑space media services.

Default behaviour: list suspected sockets and processes (read‑only).
Use --enforce to actively terminate processes and disable services.
Use --remove-services to also attempt package removal (DESCTRUCTIVE).

Safeguards:
 - Skips PIDs 1 and current script's PID
 - Confirms destructive actions unless --yes supplied

Requires: Python 3.8+, Linux, and systemd for service operations.
"""
import argparse
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Set, Tuple

MEDIA_PROC_PATTERNS = [
    r"ffmpeg", r"vlc", r"gst-launch", r"gstreamer", r"obs", r"webrtc", r"janus", r"mediasoup",
    r"kurento", r"rtmp", r"rtsp", r"arecord", r"parec", r"parecord", r"pw-cat", r"pipewire", r"pulseaudio"
]
MEDIA_PORT_HINTS = [
    1935,      # RTMP
    554,       # RTSP
    3478, 3479, 3480, 3481,  # STUN/TURN common
    8000, 8001, 8080,        # Often ad-hoc streaming
]
SERVICE_CANDIDATES = [
    "pipewire.service",
    "pipewire.socket",
    "pipewire-pulse.service",
    "pulseaudio.service",
    "pulseaudio.socket",
    "rtmp-server.service",
]
PACKAGE_CANDIDATES = [
    "pipewire", "pipewire-pulse", "pulseaudio", "obs-studio"
]

PID_EXCLUDE: Set[int] = {1, os.getpid()}

@dataclass
class SuspectProcess:
    pid: int
    cmd: str
    reason: str

@dataclass
class SuspectSocket:
    proto: str
    local: str
    peer: str
    pid: int
    proc: str

SS_CMD = ["ss", "-tupn"]  # tcp/udp, process info, numeric

PROC_PATTERN_RE = re.compile("|".join(f"({p})" for p in MEDIA_PROC_PATTERNS), re.IGNORECASE)


def run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:  # pragma: no cover
        return 1, "", str(e)


def list_sockets() -> List[SuspectSocket]:
    rc, out, err = run(SS_CMD)
    if rc != 0:
        return []
    suspects: List[SuspectSocket] = []
    for line in out.splitlines():
        if not line or line.startswith("State"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = parts[0]
        local_addr = parts[4]
        peer_addr = parts[5]
        pid = None
        proc_name = ""
        if "pid=" in line:
            m = re.search(r"pid=(\d+),?", line)
            if m:
                pid = int(m.group(1))
        if "users:" in line:
            m2 = re.search(r"\"([^\"]+)\"", line)
            if m2:
                proc_name = m2.group(1)
        # Port extraction
        try:
            port = int(local_addr.rsplit(":", 1)[1])
        except Exception:
            port = -1
        if port in MEDIA_PORT_HINTS or (proc_name and PROC_PATTERN_RE.search(proc_name)):
            suspects.append(SuspectSocket(proto, local_addr, peer_addr, pid or -1, proc_name))
    return suspects


def list_processes() -> List[SuspectProcess]:
    rc, out, err = run(["ps", "-eo", "pid=,cmd="])
    if rc != 0:
        return []
    suspects: List[SuspectProcess] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid_str, cmd = line.split(None, 1)
            pid = int(pid_str)
        except ValueError:
            continue
        if pid in PID_EXCLUDE:
            continue
        if PROC_PATTERN_RE.search(cmd):
            reason = "pattern match"
            suspects.append(SuspectProcess(pid, cmd, reason))
    return suspects


def terminate(pid: int, dry_run: bool):
    if pid in PID_EXCLUDE:
        return False, "protected PID"
    if dry_run:
        return True, "dry-run"
    try:
        os.kill(pid, 15)  # SIGTERM
    except ProcessLookupError:
        return False, "not found"
    except PermissionError:
        return False, "permission denied"
    return True, "sent SIGTERM"


def disable_service(svc: str, dry_run: bool):
    if dry_run:
        return True, "dry-run"
    rc, _, err = run(["systemctl", "disable", "--now", svc])
    if rc == 0:
        return True, "disabled"
    return False, err.strip() or "failed"


def remove_packages(pkgs: List[str], dry_run: bool):
    if dry_run:
        return True, "dry-run"
    cmd = ["bash", "-c", shlex.join(["apt-get", "-y", "purge", *pkgs]) + " >/dev/null 2>&1"]
    rc, _, _ = run(cmd)
    return rc == 0, "purged" if rc == 0 else "purge failed"


def confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N]: ").lower().startswith("y")
    except EOFError:
        return False


def main():
    p = argparse.ArgumentParser(description="Audit and neutralize outbound media streams")
    p.add_argument("--enforce", action="store_true", help="Terminate processes and disable services")
    p.add_argument("--remove-services", action="store_true", help="Also purge related packages (destructive)")
    p.add_argument("--yes", action="store_true", help="Assume yes for confirmations")
    p.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p.add_argument("--dry-run", action="store_true", help="Show actions without executing")
    args = p.parse_args()

    sockets = list_sockets()
    procs = list_processes()

    result = {
        "sockets": [s.__dict__ for s in sockets],
        "processes": [p.__dict__ for p in procs],
        "actions": [],
        "enforced": False,
        "dry_run": args.dry_run,
        "removed_packages": False,
    }

    if args.enforce:
        # Build PID set from both sources
        pid_set = {sp.pid for sp in procs if sp.pid > 1}
        pid_set.update(s.pid for s in sockets if s.pid > 1)
        for pid in sorted(pid_set):
            ok, msg = terminate(pid, args.dry_run)
            result["actions"].append({"pid": pid, "action": "terminate", "ok": ok, "msg": msg})
        for svc in SERVICE_CANDIDATES:
            ok, msg = disable_service(svc, args.dry_run)
            result["actions"].append({"service": svc, "action": "disable", "ok": ok, "msg": msg})
        result["enforced"] = True
        if args.remove_services and PACKAGE_CANDIDATES:
            if args.yes or confirm("Proceed with destructive package removal?"):
                ok, msg = remove_packages(PACKAGE_CANDIDATES, args.dry_run)
                result["actions"].append({"packages": PACKAGE_CANDIDATES, "action": "purge", "ok": ok, "msg": msg})
                result["removed_packages"] = ok
            else:
                result["actions"].append({"action": "purge", "ok": False, "msg": "cancelled"})

    if args.json:
        import json
        print(json.dumps(result, indent=2))
    else:
        if sockets:
            print("Suspect sockets:")
            for s in sockets:
                print(f"  {s.proto} {s.local} -> {s.peer} pid={s.pid} ({s.proc})")
        else:
            print("No suspect sockets detected.")
        if procs:
            print("Suspect processes:")
            for sp in procs:
                print(f"  pid={sp.pid} {sp.cmd} [{sp.reason}]")
        else:
            print("No suspect processes detected.")
        if result["actions"]:
            print("\nEnforcement actions:")
            for act in result["actions"]:
                if act.get("action") == "terminate":
                    print(f"  PID {act['pid']}: terminate -> {act['msg']}")
                elif act.get("action") == "disable":
                    print(f"  Service {act['service']}: disable -> {act['msg']}")
                elif act.get("action") == "purge":
                    print(f"  Packages {act.get('packages')}: purge -> {act['msg']}")
        elif args.enforce:
            print("No enforcement actions executed.")
        print(f"\nDry-run: {args.dry_run}  Enforced: {result['enforced']}  PackagesRemoved: {result['removed_packages']}")

    # Exit code: 0 if nothing found or successfully enforced, 1 if findings exist and not enforced
    if (sockets or procs) and not args.enforce:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(130)
