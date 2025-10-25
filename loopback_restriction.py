"""Restrict loopback network connectivity to harden local attack surface."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Dict, List, Any


IPV4_LOOPBACK_CIDR = "127.0.0.0/24"
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


def apply_loopback_block(dry_run: bool = False) -> Dict[str, Any]:
    rules_by_family = {
        "iptables": [
            ["-A", "INPUT", "-i", "lo", "-j", "DROP"],
            ["-A", "OUTPUT", "-o", "lo", "-j", "DROP"],
            ["-A", "INPUT", "-s", IPV4_LOOPBACK_CIDR, "-j", "DROP"],
            ["-A", "OUTPUT", "-d", IPV4_LOOPBACK_CIDR, "-j", "DROP"],
        ],
        "ip6tables": [
            ["-A", "INPUT", "-i", "lo", "-j", "DROP"],
            ["-A", "OUTPUT", "-o", "lo", "-j", "DROP"],
            ["-A", "INPUT", "-s", IPV6_LOOPBACK_CIDR, "-j", "DROP"],
            ["-A", "OUTPUT", "-d", IPV6_LOOPBACK_CIDR, "-j", "DROP"],
        ],
    }

    commands: List[List[str]] = []
    for binary, rule_set in rules_by_family.items():
        if not _iptables_present(binary):
            continue
        prefix = _maybe_sudo() + [binary]
        commands.extend(prefix + rule for rule in rule_set)

    if not commands:
        return {
            "success": False,
            "message": "No iptables tooling available to enforce loopback restriction.",
            "commands": [],
            "errors": [],
        }

    executed: List[str] = []
    errors: List[str] = []
    for cmd in commands:
        result = _run(cmd, dry_run=dry_run)
        executed.append(" ".join(cmd))
        if result.returncode != 0 and not dry_run:
            errors.append(f"{' '.join(cmd)} -> {result.stderr.strip()}")

    success = not errors
    message = "Loopback interface traffic blocked" if success else "Loopback restriction encountered errors"
    if dry_run:
        message = "Loopback restriction would be applied"

    return {
        "success": success,
        "message": message,
        "commands": executed,
        "errors": errors,
        "dry_run": dry_run,
    }


def preview_loopback_block() -> str:
    preview = apply_loopback_block(dry_run=True)
    if not preview.get("commands"):
        return "Loopback restriction requires iptables/ip6tables tooling."
    return "\n".join(preview["commands"])


def get_loopback_summary() -> str:
    return (
        "Loopback restriction policy:\n"
        "- IPv4 target range: {ipv4}\n"
        "- IPv6 target range: {ipv6}\n"
        "- Interfaces: lo inbound/outbound\n"
        "- Action: Drop traffic using iptables/ip6tables".format(
            ipv4=IPV4_LOOPBACK_CIDR,
            ipv6=IPV6_LOOPBACK_CIDR,
        )
    )
