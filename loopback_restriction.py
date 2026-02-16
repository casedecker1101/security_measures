"""Restrict loopback network connectivity to harden local attack surface."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Dict, List, Any


IPV4_LOOPBACK_CIDR = "127.0.0.0/8"
IPV6_LOOPBACK_CIDR = "::1/128"


def _maybe_sudo() -> List[str]:
    if os.geteuid() == 0:
        return []
    if shutil.which("sudo"):
        return ["sudo"]
    return []


def _run(cmd: List[str], dry_run: bool) -> subprocess.CompletedProcess:
    if dry_run:
        completed = subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return completed
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _iptables_present(binary: str) -> bool:
    return shutil.which(binary) is not None


def _loopback_hardening_rules() -> Dict[str, List[List[str]]]:
    return {
        "iptables": [
            ["INPUT", "-i", "lo", "-j", "ACCEPT"],
            ["OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            ["INPUT", "!", "-i", "lo", "-s", IPV4_LOOPBACK_CIDR, "-j", "DROP"],
            ["OUTPUT", "!", "-o", "lo", "-d", IPV4_LOOPBACK_CIDR, "-j", "DROP"],
        ],
        "ip6tables": [
            ["INPUT", "-i", "lo", "-j", "ACCEPT"],
            ["OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            ["INPUT", "!", "-i", "lo", "-s", IPV6_LOOPBACK_CIDR, "-j", "DROP"],
            ["OUTPUT", "!", "-o", "lo", "-d", IPV6_LOOPBACK_CIDR, "-j", "DROP"],
        ],
    }


def _apply_loopback_rules(
    *,
    rules_by_family: Dict[str, List[List[str]]],
    action: str,
    dry_run: bool,
) -> Dict[str, Any]:
    commands: List[List[str]] = []
    for binary, rule_set in rules_by_family.items():
        if not _iptables_present(binary):
            continue
        prefix = _maybe_sudo() + [binary]
        for rule in rule_set:
            commands.append(prefix + [action] + rule)

    if not commands:
        return {
            "success": False,
            "message": "No iptables tooling available to enforce loopback hardening.",
            "commands": [],
            "errors": [],
        }

    executed: List[str] = []
    errors: List[str] = []
    skipped: List[str] = []
    for cmd in commands:
        if dry_run:
            executed.append(" ".join(cmd))
            continue

        check_cmd = cmd[:]
        check_cmd[check_cmd.index(action)] = "-C"
        check_result = _run(check_cmd, dry_run=False)

        if action == "-A" and check_result.returncode == 0:
            skipped.append(" ".join(cmd))
            continue
        if action == "-D" and check_result.returncode != 0:
            skipped.append(" ".join(cmd))
            continue

        result = _run(cmd, dry_run=False)
        executed.append(" ".join(cmd))
        if result.returncode != 0:
            errors.append(f"{' '.join(cmd)} -> {result.stderr.strip()}")

    success = not errors
    message = "Loopback hardening applied" if action == "-A" else "Loopback hardening restored"
    if dry_run:
        message = "Loopback hardening would be applied" if action == "-A" else "Loopback hardening would be restored"

    payload = {
        "success": success,
        "message": message,
        "commands": executed,
        "errors": errors,
        "dry_run": dry_run,
    }
    if skipped:
        payload["skipped"] = skipped
    return payload


def apply_loopback_hardening(dry_run: bool = False) -> Dict[str, Any]:
    rules_by_family = _loopback_hardening_rules()
    return _apply_loopback_rules(rules_by_family=rules_by_family, action="-A", dry_run=dry_run)


def restore_loopback_hardening(dry_run: bool = False) -> Dict[str, Any]:
    rules_by_family = _loopback_hardening_rules()
    return _apply_loopback_rules(rules_by_family=rules_by_family, action="-D", dry_run=dry_run)


def apply_loopback_block(dry_run: bool = False) -> Dict[str, Any]:
    """Deprecated: use apply_loopback_hardening for anti-spoofing rules."""
    return apply_loopback_hardening(dry_run=dry_run)


def preview_loopback_hardening() -> str:
    preview = apply_loopback_hardening(dry_run=True)
    if not preview.get("commands"):
        return "Loopback hardening requires iptables/ip6tables tooling."
    return "\n".join(preview["commands"])


def preview_loopback_restore() -> str:
    preview = restore_loopback_hardening(dry_run=True)
    if not preview.get("commands"):
        return "Loopback hardening restore requires iptables/ip6tables tooling."
    return "\n".join(preview["commands"])


def preview_loopback_block() -> str:
    return preview_loopback_hardening()


def get_loopback_summary() -> str:
    return (
        "Loopback hardening policy:\n"
        "- IPv4 target range: {ipv4}\n"
        "- IPv6 target range: {ipv6}\n"
        "- Interfaces: lo inbound/outbound\n"
        "- Action: Accept lo, drop spoofed loopback traffic".format(
            ipv4=IPV4_LOOPBACK_CIDR,
            ipv6=IPV6_LOOPBACK_CIDR,
        )
    )
