"""Utilities for blocking remote access and communication applications via firewall rules."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, List

REMOTE_APPS = sorted({
    "AnyDesk",
    "Apple Remote Desktop (ARD)",
    "BitTorrent",
    "Box",
    "Chrome Remote Desktop",
    "Citrix Virtual Apps and Desktops",
    "ConnectWise Control (ScreenConnect)",
    "Dameware Remote Support",
    "Discord",
    "Dropbox",
    "Epic Games",
    "Facebook",
    "FTP",
    "GoToMyPC",
    "Google Drive",
    "Instagram",
    "IPsec",
    "Jitsi Meet",
    "Line",
    "LogMeIn Pro",
    "L2TP",
    "Microsoft Remote Desktop (RDP)",
    "Microsoft Teams",
    "Netflix",
    "NoMachine",
    "OneDrive",
    "OpenSSH",
    "OpenVPN",
    "PlayStation Network",
    "Psiphon",
    "RealVNC",
    "RemotePC by IDrive",
    "RustDesk",
    "SFTP",
    "Shadowsocks",
    "Skype",
    "Slack",
    "Snapchat",
    "Spotify",
    "Splashtop",
    "Steam",
    "TeamViewer",
    "Telegram",
    "TikTok",
    "Tor",
    "Twitch",
    "Twitter",
    "UltraVNC",
    "VMware Horizon",
    "Webex",
    "WeChat",
    "WhatsApp",
    "WireGuard",
    "YouTube",
    "Zoho Assist",
    "Zoom",
})

PORTS = sorted({
    22, 53, 80, 123, 443, 500, 1080, 1194, 1494, 1701, 1723, 17500, 1935, 21115,
    21116, 2598, 27015, 27036, 3074, 3283, 3390, 3391, 3478, 3479, 3480, 3481,
    3659, 4000, 4172, 4244, 4443, 4500, 5000, 50001, 50002, 5060, 5061, 5129,
    5222, 5223, 5224, 5228, 5229, 5230, 5349, 5500, 5800, 5801, 5802, 5803, 5900,
    5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5938, 5939, 6010, 6129,
    6568, 6783, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 68892,
    68893, 68894, 68895, 68896, 68897, 68898, 68899, 8080, 8081, 8088, 8443, 8801,
    8802, 8803, 8804, 8805, 9030, 9080, 9150
})

# Ensure canonical port list ordering without typos (remove out-of-range values)
PORTS = [p for p in PORTS if isinstance(p, int) and 0 < p < 65536]


@dataclass
class CommandResult:
    command: List[str]
    returncode: int
    stderr: str = ""


def _chunked(seq: Iterable[int], size: int) -> Iterable[List[int]]:
    seq_list = list(seq)
    for idx in range(0, len(seq_list), size):
        yield seq_list[idx:idx + size]


def _maybe_sudo() -> List[str]:
    if os.geteuid() == 0:
        return []
    # Allow for environments without sudo (e.g., Termux)
    if shutil.which("sudo"):
        return ["sudo"]
    return []


def _run_command(cmd: List[str], dry_run: bool) -> CommandResult:
    if dry_run:
        return CommandResult(command=cmd, returncode=0)
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return CommandResult(command=cmd, returncode=completed.returncode, stderr=completed.stderr.strip())
    except Exception as exc:  # pragma: no cover - defensive guard
        return CommandResult(command=cmd, returncode=1, stderr=str(exc))


def _build_iptables_commands(binary: str) -> List[List[str]]:
    commands: List[List[str]] = []
    if shutil.which(binary) is None:
        return commands

    prefix = _maybe_sudo()
    for chain in ("INPUT", "OUTPUT"):
        for proto in ("tcp", "udp"):
            for ports in _chunked(PORTS, 15):
                cmd = prefix + [binary, "-A", chain, "-p", proto]
                if len(ports) == 1:
                    cmd += ["--dport", str(ports[0])]
                else:
                    cmd += ["-m", "multiport", "--dports", ",".join(str(p) for p in ports)]
                cmd += ["-j", "REJECT"]
                commands.append(cmd)
    return commands


def _build_ufw_commands() -> List[List[str]]:
    if shutil.which("ufw") is None:
        return []
    prefix = _maybe_sudo()
    commands: List[List[str]] = []
    for proto in ("tcp", "udp"):
        for ports in _chunked(PORTS, 15):
            cmd = prefix + ["ufw", "deny"]
            if len(ports) == 1:
                cmd.append(f"{ports[0]}/{proto}")
            else:
                cmd.append(f"{','.join(str(p) for p in ports)}/{proto}")
            cmd.append("comment")
            cmd.append("Remote app block")
            commands.append(cmd)
    return commands


def apply_remote_app_block(dry_run: bool = False) -> dict:
    """Apply firewall rules that block known remote access/streaming applications."""
    commands = _build_iptables_commands("iptables") + _build_iptables_commands("ip6tables") + _build_ufw_commands()

    if not commands:
        return {
            "success": False,
            "message": "No firewall tooling (iptables/ufw) detected; nothing applied.",
            "apps": REMOTE_APPS,
            "ports": PORTS,
        }

    failures: List[CommandResult] = []
    executed: List[CommandResult] = []

    for cmd in commands:
        result = _run_command(cmd, dry_run=dry_run)
        executed.append(result)
        if result.returncode != 0:
            failures.append(result)

    success = len(failures) == 0
    message = "Remote-application firewall blocks applied" if success else "Remote-application firewall block encountered errors"

    return {
        "success": success,
        "message": message,
        "apps": REMOTE_APPS,
        "ports": PORTS,
        "commands": [" ".join(cmd_result.command) for cmd_result in executed],
        "errors": [f"{' '.join(fr.command)}: {fr.stderr}" for fr in failures if fr.stderr],
        "dry_run": dry_run,
    }


def preview_remote_app_block() -> str:
    commands = _build_iptables_commands("iptables") + _build_iptables_commands("ip6tables") + _build_ufw_commands()
    if not commands:
        return "No iptables/ufw tooling detected; preview unavailable."
    rendered = "\n".join(" ".join(cmd) for cmd in commands)
    return (
        "The following commands would be executed to block remote applications:\n"
        f"{rendered}\n"
        "Affected applications: " + ", ".join(REMOTE_APPS)
    )


def get_remote_app_summary() -> str:
    platform_info = platform.system()
    return (
        "Remote/communication application block summary:\n"
        f"Detected platform: {platform_info}\n"
        f"Applications targeted: {', '.join(REMOTE_APPS)}\n"
        f"Ports covered ({len(PORTS)} total): {', '.join(str(p) for p in PORTS)}"
    )