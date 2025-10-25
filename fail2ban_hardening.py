"""Utilities to install, enable, and reload fail2ban using existing configuration."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any

CONFIG_DIR = Path("/etc/fail2ban")
JAIL_DIR = CONFIG_DIR / "jail.d"


def _maybe_sudo() -> List[str]:
    if os.geteuid() == 0:
        return []
    if shutil.which("sudo"):
        return ["sudo"]
    return []


def _run(cmd: List[str], dry_run: bool = False) -> subprocess.CompletedProcess:
    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _fail2ban_installed() -> bool:
    return shutil.which("fail2ban-client") is not None


def _systemctl_available() -> bool:
    return shutil.which("systemctl") is not None


def install_fail2ban(dry_run: bool = False) -> Dict[str, Any]:
    if _fail2ban_installed():
        return {
            "success": True,
            "message": "fail2ban already installed",
            "command": "",
            "dry_run": dry_run,
        }

    cmd = _maybe_sudo() + ["apt-get", "update", "-qq"]
    install_cmd = _maybe_sudo() + ["apt-get", "install", "-y", "fail2ban"]

    update_result = _run(cmd, dry_run=dry_run)
    install_result = _run(install_cmd, dry_run=dry_run)

    success = update_result.returncode == 0 and install_result.returncode == 0
    message = "fail2ban installed" if success else "Failed to install fail2ban"

    return {
        "success": success,
        "message": message,
        "command": " ".join(install_cmd),
        "dry_run": dry_run,
        "stderr": install_result.stderr.strip() if install_result.stderr else "",
    }


def enable_fail2ban_service(dry_run: bool = False) -> Dict[str, Any]:
    commands: List[List[str]]
    if _systemctl_available():
        commands = [
            _maybe_sudo() + ["systemctl", "enable", "fail2ban"],
            _maybe_sudo() + ["systemctl", "start", "fail2ban"],
        ]
    else:
        commands = [
            _maybe_sudo() + ["service", "fail2ban", "start"],
        ]

    errors: List[str] = []
    executed: List[str] = []
    for cmd in commands:
        executed.append(" ".join(cmd))
        result = _run(cmd, dry_run=dry_run)
        if result.returncode != 0 and not dry_run:
            errors.append(result.stderr.strip())

    success = not errors
    message = "fail2ban service enabled" if success else "Failed to enable fail2ban service"
    if dry_run:
        message = "fail2ban service would be enabled"

    return {
        "success": success,
        "message": message,
        "commands": executed,
        "errors": errors,
        "dry_run": dry_run,
    }


def _discover_jail_files() -> List[Dict[str, Any]]:
    files: List[Path] = []
    if CONFIG_DIR.exists():
        files.extend(CONFIG_DIR.glob("jail.conf"))
        files.extend(CONFIG_DIR.glob("jail.local"))
    if JAIL_DIR.exists():
        files.extend(sorted(JAIL_DIR.glob("*.conf")))
        files.extend(sorted(JAIL_DIR.glob("*.local")))

    jail_details: List[Dict[str, Any]] = []
    enabled_re = re.compile(r"^\s*enabled\s*=\s*(true|1|yes)", re.IGNORECASE)

    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except Exception:
            content = ""
        enabled = bool(enabled_re.search(content))
        jail_details.append(
            {
                "path": str(path),
                "enabled": enabled,
                "size": path.stat().st_size if path.exists() else 0,
            }
        )
    return jail_details


def _list_active_jails(dry_run: bool = False) -> List[str]:
    if not _fail2ban_installed() or dry_run:
        return []
    cmd = _maybe_sudo() + ["fail2ban-client", "status"]
    result = _run(cmd, dry_run=False)
    if result.returncode != 0:
        return []
    for line in result.stdout.splitlines():
        if "Jail list:" in line:
            parts = line.split(":", 1)
            if len(parts) < 2:
                continue
            jail_list = parts[1].strip()
            if jail_list:
                return [j.strip() for j in jail_list.split(",") if j.strip()]
    return []


def reload_fail2ban(dry_run: bool = False) -> Dict[str, Any]:
    cmd = _maybe_sudo() + ["fail2ban-client", "reload"]
    result = _run(cmd, dry_run=dry_run)
    success = result.returncode == 0
    if dry_run:
        message = "fail2ban would be reloaded"
    else:
        message = "fail2ban reloaded" if success else "fail2ban reload failed"
    return {
        "success": success,
        "message": message,
        "command": " ".join(cmd),
        "stderr": result.stderr.strip() if result.stderr else "",
        "dry_run": dry_run,
    }


def apply_fail2ban_hardening(dry_run: bool = False) -> Dict[str, Any]:
    installation = install_fail2ban(dry_run=dry_run)
    service = enable_fail2ban_service(dry_run=dry_run)
    reload_result = reload_fail2ban(dry_run=dry_run)

    jail_files = _discover_jail_files()
    active_jails = _list_active_jails(dry_run=dry_run)

    success = all(
        step.get("success", False)
        for step in (installation, service, reload_result)
    )

    return {
        "success": success,
        "message": "fail2ban hardened" if success else "fail2ban hardening encountered issues",
        "installation": installation,
        "service": service,
        "reload": reload_result,
        "jail_files": jail_files,
        "active_jails": active_jails,
        "dry_run": dry_run,
    }


def preview_fail2ban_hardening() -> str:
    details = apply_fail2ban_hardening(dry_run=True)
    lines = [details.get("message", "fail2ban hardening preview")]
    lines.append("Commands to execute:")
    install_cmd = details.get("installation", {}).get("command")
    if install_cmd:
        lines.append(f"- {install_cmd}")
    for cmd in details.get("service", {}).get("commands", []):
        lines.append(f"- {cmd}")
    reload_cmd = details.get("reload", {}).get("command")
    if reload_cmd:
        lines.append(f"- {reload_cmd}")
    lines.append("Detected jail configuration files:")
    for jail in details.get("jail_files", []):
        enabled_flag = "enabled" if jail["enabled"] else "disabled"
        lines.append(f"  * {jail['path']} ({enabled_flag})")
    return "\n".join(lines)


def get_fail2ban_summary() -> str:
    installed = _fail2ban_installed()
    jail_files = _discover_jail_files()
    active_jails = _list_active_jails()
    lines = ["fail2ban summary:"]
    lines.append(f"- Installed: {'yes' if installed else 'no'}")
    lines.append(f"- Config files detected: {len(jail_files)}")
    if active_jails:
        lines.append("- Active jails: " + ", ".join(active_jails))
    else:
        lines.append("- Active jails: none detected")
    return "\n".join(lines)