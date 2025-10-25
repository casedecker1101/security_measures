"""Install and restore firewall tooling without losing existing rules."""

from __future__ import annotations

import shutil
import subprocess
import os
from pathlib import Path
from typing import Dict, List, Any

UFW_PACKAGE = "ufw"
IPTABLES_PACKAGES = ["iptables", "iptables-persistent"]
UFW_CONFIG_DIR = Path("/etc/ufw")
IPTABLES_RULES_V4 = Path("/etc/iptables/rules.v4")
IPTABLES_RULES_V6 = Path("/etc/iptables/rules.v6")


def _maybe_sudo() -> List[str]:
    if shutil.which("sudo") and os.geteuid() != 0:
        return ["sudo"]
    return []


def _run(cmd: List[str], dry_run: bool = False) -> subprocess.CompletedProcess:
    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _package_installed(package: str) -> bool:
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Status}", package],
        capture_output=True,
        text=True,
        check=False,
    )
    return "install ok installed" in result.stdout


def install_package(package: str, *, dry_run: bool = False, update: bool = True) -> Dict[str, Any]:
    if _package_installed(package):
        return {
            "success": True,
            "message": f"{package} already installed",
            "commands": [],
            "dry_run": dry_run,
            "stderr": "",
        }

    commands: List[List[str]] = []
    if update:
        commands.append(_maybe_sudo() + ["apt-get", "update", "-qq"])
    commands.append(_maybe_sudo() + ["apt-get", "install", "-y", package])

    stderr_parts: List[str] = []
    success = True
    for index, command in enumerate(commands):
        result = _run(command, dry_run=dry_run)
        if result.returncode != 0 and not dry_run:
            success = False
        if result.stderr:
            stderr_parts.append(result.stderr.strip())
        if not success:
            break

    message = f"{package} installed" if success else f"Failed to install {package}"
    return {
        "success": success,
        "message": message,
        "commands": [" ".join(cmd) for cmd in commands],
        "dry_run": dry_run,
        "stderr": "\n".join(stderr_parts),
    }


def install_firewall_packages(*, dry_run: bool = False) -> Dict[str, Any]:
    steps: List[Dict[str, Any]] = []

    ufw_step = install_package(UFW_PACKAGE, dry_run=dry_run)
    steps.append({"name": "ufw_install", **ufw_step})

    iptables_results: List[Dict[str, Any]] = []
    for index, package in enumerate(IPTABLES_PACKAGES):
        iptables_results.append(
            install_package(package, dry_run=dry_run, update=index == 0)
        )
    for package, result in zip(IPTABLES_PACKAGES, iptables_results):
        steps.append({"name": f"{package}_install", **result})

    restore_step = restore_current_configuration(dry_run=dry_run)
    steps.append({"name": "restore_configuration", **restore_step})

    success = all(step.get("success", False) for step in steps)
    message = "Firewall tooling ensured"
    if not success:
        message = "Firewall tooling encountered issues"
    return {
        "success": success,
        "message": message,
        "steps": steps,
        "dry_run": dry_run,
    }


def restore_current_configuration(*, dry_run: bool = False) -> Dict[str, Any]:
    commands: List[str] = []
    warnings: List[str] = []
    errors: List[str] = []

    ufw_actions = _apply_ufw_configuration(dry_run=dry_run)
    commands.extend(ufw_actions["commands"])
    warnings.extend(ufw_actions["warnings"])
    errors.extend(ufw_actions["errors"])

    iptables_actions = _apply_iptables_rules(dry_run=dry_run)
    commands.extend(iptables_actions["commands"])
    warnings.extend(iptables_actions["warnings"])
    errors.extend(iptables_actions["errors"])

    success = not errors
    return {
        "success": success,
        "message": "Existing configuration restored" if success else "Configuration restore encountered issues",
        "commands": commands,
        "warnings": warnings,
        "errors": errors,
        "dry_run": dry_run,
    }


def _apply_ufw_configuration(*, dry_run: bool = False) -> Dict[str, List[str]]:
    commands: List[str] = []
    warnings: List[str] = []
    errors: List[str] = []

    if not UFW_CONFIG_DIR.exists():
        warnings.append("No UFW configuration directory found; skipping reload")
        return {"commands": commands, "warnings": warnings, "errors": errors}

    enable_cmd = _maybe_sudo() + ["systemctl", "enable", "--now", "ufw"]
    reload_cmd = _maybe_sudo() + ["ufw", "reload"]
    for cmd in (enable_cmd, reload_cmd):
        commands.append(" ".join(cmd))
        result = _run(cmd, dry_run=dry_run)
        if result.returncode != 0 and not dry_run:
            errors.append(result.stderr.strip() or "Command failed")

    return {"commands": commands, "warnings": warnings, "errors": errors}


def _apply_iptables_rules(*, dry_run: bool = False) -> Dict[str, List[str]]:
    commands: List[str] = []
    warnings: List[str] = []
    errors: List[str] = []

    service_cmd = _maybe_sudo() + ["systemctl", "enable", "--now", "netfilter-persistent"]
    commands.append(" ".join(service_cmd))
    result = _run(service_cmd, dry_run=dry_run)
    if result.returncode != 0 and not dry_run:
        warnings.append("Unable to enable netfilter-persistent service")

    if IPTABLES_RULES_V4.exists():
        cmd = _maybe_sudo() + ["iptables-restore", str(IPTABLES_RULES_V4)]
        commands.append(" ".join(cmd))
        result = _run(cmd, dry_run=dry_run)
        if result.returncode != 0 and not dry_run:
            errors.append(result.stderr.strip() or "Failed to restore IPv4 rules")
    else:
        warnings.append("No IPv4 rules file detected")

    if IPTABLES_RULES_V6.exists():
        cmd6 = _maybe_sudo() + ["ip6tables-restore", str(IPTABLES_RULES_V6)]
        commands.append(" ".join(cmd6))
        result = _run(cmd6, dry_run=dry_run)
        if result.returncode != 0 and not dry_run:
            errors.append(result.stderr.strip() or "Failed to restore IPv6 rules")
    else:
        warnings.append("No IPv6 rules file detected")

    return {"commands": commands, "warnings": warnings, "errors": errors}


def preview_firewall_installation() -> str:
    result = install_firewall_packages(dry_run=True)
    lines = ["Preview of firewall tooling installation:"]
    for step in result.get("steps", []):
        lines.append(f"- {step['name']}: {step['message']}")
        for command in step.get("commands", []):
            lines.append(f"    {command}")
    return "\n".join(lines)


def get_firewall_installation_summary() -> str:
    lines = ["Firewall tooling summary:"]
    lines.append(f"- ufw installed: {'yes' if _package_installed(UFW_PACKAGE) else 'no'}")
    lines.append(f"- iptables present: {'yes' if shutil.which('iptables') else 'no'}")
    lines.append(f"- IPv4 rules file: {'present' if IPTABLES_RULES_V4.exists() else 'missing'}")
    lines.append(f"- IPv6 rules file: {'present' if IPTABLES_RULES_V6.exists() else 'missing'}")
    return "\n".join(lines)
