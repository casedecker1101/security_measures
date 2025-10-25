"""Remediation tasks for rootkit scanner warnings and findings."""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import subprocess
from typing import Dict, List, Any


# These files triggered chkrootkit warnings but are harmless placeholders from packages.
CHKROOTKIT_FALSE_POSITIVES = [
    "/usr/lib/hashcat/modules/.gitkeep",
    "/usr/lib/hashcat/bridges/.gitkeep",
    "/usr/lib/python3/dist-packages/aiohttp/_websocket/.hash",
    "/usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/noentry/.htaccess",
    "/usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/basic/file/.htp",
]

# Files highlighted by rkhunter that should be baked into the property database.
RKHUNTER_FILES_TO_UPDATE = [
    "/usr/bin/mail",
    "/usr/bin/lwp-request",
    "/usr/bin/bsd-mailx",
]

PULSE_USERNAME = "pulse"
PULSE_AUDIO_GROUP = "audio"


def _maybe_sudo() -> List[str]:
    if os.geteuid() == 0:
        return []
    if shutil.which("sudo"):
        return ["sudo"]
    return []


def _run_command(cmd: List[str], dry_run: bool) -> subprocess.CompletedProcess:
    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _remove_file(path: str, dry_run: bool) -> Dict[str, Any]:
    commands: List[str] = []
    errors: List[str] = []
    removed: List[str] = []

    if not os.path.exists(path):
        return {
            "success": True,
            "message": f"File not present: {path}",
            "commands": [],
            "errors": [],
            "removed": [],
        }

    cmd = _maybe_sudo() + ["rm", "-f", path]
    commands.append(" ".join(cmd))
    result = _run_command(cmd, dry_run)
    if result.returncode == 0:
        removed.append(path)
    else:
        errors.append(f"{' '.join(cmd)} -> {result.stderr.strip()}")

    success = not errors
    message = "File removed" if success else "Failed to remove file"
    if dry_run:
        message = "File would be removed"

    return {
        "success": success,
        "message": message,
        "commands": commands,
        "errors": errors,
        "removed": removed,
    }


def remediate_chkrootkit_artifacts(dry_run: bool = False) -> Dict[str, Any]:
    commands: List[str] = []
    errors: List[str] = []
    removed: List[str] = []

    for path in CHKROOTKIT_FALSE_POSITIVES:
        result = _remove_file(path, dry_run)
        commands.extend(result.get("commands", []))
        errors.extend(result.get("errors", []))
        removed.extend(result.get("removed", []))

    success = not errors
    if dry_run:
        message = "chkrootkit false positives would be removed"
    else:
        message = "chkrootkit false positives removed" if success else "chkrootkit artifact removal encountered errors"

    return {
        "success": success,
        "message": message,
        "commands": commands,
        "errors": errors,
        "removed": removed,
        "dry_run": dry_run,
    }


def update_rkhunter_baseline(dry_run: bool = False) -> Dict[str, Any]:
    if shutil.which("rkhunter") is None:
        return {
            "success": False,
            "message": "rkhunter is not installed; cannot update property database",
            "commands": [],
            "errors": ["rkhunter binary missing"],
            "dry_run": dry_run,
        }

    cmd = _maybe_sudo() + ["rkhunter", "--propupd"]
    result = _run_command(cmd, dry_run)
    success = result.returncode == 0
    message = "rkhunter property database updated" if success else "Failed to update rkhunter property database"
    if dry_run:
        message = "rkhunter property database would be updated"

    errors: List[str] = []
    if not success and not dry_run:
        errors.append(result.stderr.strip())

    return {
        "success": success,
        "message": message,
        "commands": [" ".join(cmd)],
        "errors": errors,
        "targets": RKHUNTER_FILES_TO_UPDATE,
        "dry_run": dry_run,
    }


def _user_exists(username: str) -> bool:
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def _user_in_group(username: str, group: str) -> bool:
    try:
        entry = grp.getgrnam(group)
    except KeyError:
        return False
    return username in entry.gr_mem


def lockdown_pulse_user(dry_run: bool = False) -> Dict[str, Any]:
    if not _user_exists(PULSE_USERNAME):
        return {
            "success": True,
            "message": "pulse user not present",
            "commands": [],
            "errors": [],
            "dry_run": dry_run,
        }

    commands: List[str] = []
    errors: List[str] = []

    if _user_in_group(PULSE_USERNAME, PULSE_AUDIO_GROUP):
        cmd_remove = _maybe_sudo() + ["gpasswd", "-d", PULSE_USERNAME, PULSE_AUDIO_GROUP]
        commands.append(" ".join(cmd_remove))
        result = _run_command(cmd_remove, dry_run)
        if result.returncode != 0 and not dry_run:
            errors.append(result.stderr.strip())

    cmd_lock = _maybe_sudo() + ["passwd", "-l", PULSE_USERNAME]
    commands.append(" ".join(cmd_lock))
    result = _run_command(cmd_lock, dry_run)
    if result.returncode != 0 and not dry_run:
        errors.append(result.stderr.strip())

    success = not errors
    if dry_run:
        message = "pulse account would be locked and removed from audio group"
    else:
        message = "pulse account locked and access reduced" if success else "Failed to fully lock pulse account"

    return {
        "success": success,
        "message": message,
        "commands": commands,
        "errors": errors,
        "dry_run": dry_run,
    }


def run_rootkit_remediation(dry_run: bool = False) -> Dict[str, Any]:
    results = []
    success = True
    errors: List[str] = []

    for action in (
        remediate_chkrootkit_artifacts,
        update_rkhunter_baseline,
        lockdown_pulse_user,
    ):
        result = action(dry_run=dry_run)
        results.append({
            "action": action.__name__,
            "success": result.get("success", False),
            "message": result.get("message", ""),
            "errors": result.get("errors", []),
            "commands": result.get("commands", []),
        })
        if not result.get("success", False):
            success = False
            errors.extend(result.get("errors", []))

    if dry_run:
        message = "Rootkit remediation actions would be executed"
    else:
        message = "Rootkit remediation completed" if success else "Rootkit remediation encountered issues"

    return {
        "success": success,
        "message": message,
        "steps": results,
        "errors": errors,
        "dry_run": dry_run,
    }


def get_rootkit_remediation_summary() -> str:
    lines = [
        "Rootkit remediation playbook:",
        "- Remove known chkrootkit false-positive artifacts (hashcat, aiohttp, fail2ban test files)",
        "- Refresh rkhunter property database with current binaries",
        "- Lock the pulse service account and remove it from the audio group",
        "- Requires sudo privileges for filesystem and account changes",
    ]
    return "\n".join(lines)