"""Firewall configuration export and hardening helpers for Flatline Dixie.

This module is adapted from the original standalone
`import/firewall_security_exporter.py` script so that the functionality can be
used programmatically by the rest of the application (chat interface, CLI, and
security hardening workflows).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

DEFAULT_EXPORT_DIR = Path(__file__).resolve().parent.parent / "import"


@dataclass
class CommandResult:
    command: str
    stdout: str
    returncode: int


@dataclass
class FirewallSecurityContext:
    dry_run: bool = False
    output_dir: Optional[Path] = None
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    export_data: Dict[str, object] = field(default_factory=lambda: {
        "timestamp": None,
        "firewalld": {},
        "ufw": {},
        "security_applied": []
    })

    def __post_init__(self) -> None:
        self.export_data["timestamp"] = self.timestamp
        if self.output_dir is None:
            self.output_dir = DEFAULT_EXPORT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Command helpers
    # ------------------------------------------------------------------
    def _run_command(self, command: str, check: bool = False) -> CommandResult:
        """Execute *command* via the shell and return the output."""
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        stdout = result.stdout.strip()
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command, stdout)
        return CommandResult(command=command, stdout=stdout, returncode=result.returncode)

    def _tool_exists(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------
    def collect_firewalld_state(self) -> None:
        if not self._tool_exists("firewall-cmd"):
            return

        data: Dict[str, object] = {}
        result = self._run_command("systemctl is-active firewalld")
        data["active"] = result.stdout == "active"

        result = self._run_command("sudo firewall-cmd --get-default-zone")
        if result.returncode == 0:
            data["default_zone"] = result.stdout

        result = self._run_command("sudo firewall-cmd --get-active-zones")
        if result.returncode == 0:
            data["active_zones"] = result.stdout

        result = self._run_command("sudo firewall-cmd --list-all-zones")
        if result.returncode == 0:
            data["all_zones"] = result.stdout

        result = self._run_command("sudo firewall-cmd --get-services")
        if result.returncode == 0:
            data["available_services"] = result.stdout.split()

        result = self._run_command("sudo firewall-cmd --list-services")
        if result.returncode == 0:
            data["enabled_services"] = result.stdout.split()

        result = self._run_command("sudo firewall-cmd --list-ports")
        if result.returncode == 0:
            data["open_ports"] = result.stdout.split()

        self.export_data["firewalld"] = data

    def collect_ufw_state(self) -> None:
        if not self._tool_exists("ufw"):
            return

        data: Dict[str, object] = {}
        result = self._run_command("sudo ufw status verbose")
        if result.returncode == 0:
            data["status"] = result.stdout

        result = self._run_command("sudo ufw status numbered")
        if result.returncode == 0:
            data["rules_numbered"] = result.stdout

        result = self._run_command("systemctl is-active ufw")
        data["active"] = result.stdout == "active"

        result = self._run_command("sudo ufw app list")
        if result.returncode == 0:
            data["available_apps"] = result.stdout

        self.export_data["ufw"] = data

    # ------------------------------------------------------------------
    # Hardening helpers
    # ------------------------------------------------------------------
    def apply_firewalld_hardening(self) -> List[str]:
        actions: List[str] = []
        if not self._tool_exists("firewall-cmd"):
            return actions

        def perform(description: str, command: str) -> None:
            if self.dry_run:
                actions.append(f"Would {description}")
                return
            result = self._run_command(command)
            if result.returncode == 0:
                actions.append(description)

        perform("enable firewalld service", "sudo systemctl enable firewalld")
        perform("start firewalld service", "sudo systemctl start firewalld")
        perform("set default zone to public", "sudo firewall-cmd --set-default-zone=public")

        risky_services = [
            "telnet", "ftp", "tftp", "rsh", "rlogin", "finger",
            "netbios-ns", "netbios-dgm", "netbios-ssn", "microsoft-ds",
        ]
        for service in risky_services:
            perform(f"remove service {service}", f"sudo firewall-cmd --permanent --remove-service={service}")

        actions.append("Panic mode available: firewall-cmd --panic-on")
        perform("reload firewalld configuration", "sudo firewall-cmd --reload")

        if not isinstance(self.export_data.get("security_applied"), list):
            self.export_data["security_applied"] = []
        if not isinstance(self.export_data.get("security_applied"), list):
            self.export_data["security_applied"] = []
        if not isinstance(self.export_data.get("security_applied"), list):
            self.export_data["security_applied"] = []
        self.export_data["security_applied"].extend(actions)
        return actions

    def apply_ufw_hardening(self) -> List[str]:
        actions: List[str] = []
        if not self._tool_exists("ufw"):
            return actions

        def perform(description: str, command: str) -> None:
            if self.dry_run:
                actions.append(f"Would {description}")
                return
            result = self._run_command(command)
            if result.returncode == 0:
                actions.append(description)

        perform("set default deny incoming", "sudo ufw default deny incoming")
        perform("set default allow outgoing", "sudo ufw default allow outgoing")
        perform("set default deny routed", "sudo ufw default deny routed")
        perform("enable UFW logging", "sudo ufw logging on")

        risky_ports: List[Tuple[int, str, str]] = [
            (23, "tcp", "Telnet"),
            (21, "tcp", "FTP"),
            (69, "udp", "TFTP"),
            (135, "tcp", "MS RPC"),
            (137, "udp", "NetBIOS NS"),
            (138, "udp", "NetBIOS DGM"),
            (139, "tcp", "NetBIOS SSN"),
            (445, "tcp", "SMB"),
        ]

        for port, proto, desc in risky_ports:
            perform(
                f"deny {port}/{proto} ({desc})",
                f"sudo ufw deny {port}/{proto} comment '{desc}'",
            )

        perform("apply SSH rate limiting", "sudo ufw limit 22/tcp comment 'SSH rate limit'")
        perform("enable UFW firewall", "yes | sudo ufw enable")

        self.export_data["security_applied"].extend(actions)
        return actions

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------
    def save_export(self) -> Optional[Path]:
        if self.dry_run:
            return None
        output_dir = self.output_dir if self.output_dir is not None else DEFAULT_EXPORT_DIR
        export_path = output_dir / f"firewall_export_{self.timestamp}.json"
        with export_path.open("w") as fh:
            json.dump(self.export_data, fh, indent=2)
        return export_path

    def generate_report(self) -> Optional[Path]:
        if self.dry_run:
            return None
        output_dir = self.output_dir if self.output_dir is not None else DEFAULT_EXPORT_DIR
        report_path = output_dir / f"firewall_security_report_{self.timestamp}.txt"
        with report_path.open("w") as fh:
            fh.write(self.build_summary())
        return report_path

    def build_summary(self) -> str:
        firewalld = self.export_data.get("firewalld", {})
        ufw = self.export_data.get("ufw", {})
        applied = self.export_data.get("security_applied", [])

        lines = [
            "=" * 80,
            "FIREWALL SECURITY REPORT",
            f"Generated: {self.timestamp}",
            "=" * 80,
            "",
            "FIREWALLD CONFIGURATION",
            "-" * 80,
        ]

        if firewalld:
            lines.append(f"Status: {'Active' if firewalld.get('active') else 'Inactive'}")
            lines.append(f"Default Zone: {firewalld.get('default_zone', 'N/A')}")
            lines.append(f"Enabled Services: {', '.join(firewalld.get('enabled_services', []))}")
            lines.append(f"Open Ports: {', '.join(firewalld.get('open_ports', []))}")
            if firewalld.get("all_zones"):
                lines.extend(["", "All Zones Configuration:", firewalld["all_zones"]])
        else:
            lines.append("firewalld not configured or unavailable")

        lines.extend(["", "UFW CONFIGURATION", "-" * 80])
        if ufw:
            lines.append(f"Status: {'Active' if ufw.get('active') else 'Inactive'}")
            if ufw.get("status"):
                lines.extend(["", "UFW Status:", ufw["status"]])
            if ufw.get("rules_numbered"):
                lines.extend(["", "UFW Rules:", ufw["rules_numbered"]])
        else:
            lines.append("ufw not configured or unavailable")

        lines.extend(["", "SECURITY HARDENING APPLIED", "-" * 80])
        if applied:
            lines.extend([f"✓ {item}" for item in applied])
        else:
            lines.append("No firewall hardening has been applied yet")

        return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------
# Module level helper functions
# ----------------------------------------------------------------------

def export_firewall_security(
    *,
    apply_hardening: bool = False,
    dry_run: bool = False,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Collect firewall configuration and optionally apply hardening."""
    context = FirewallSecurityContext(dry_run=dry_run, output_dir=output_dir)
    context.collect_firewalld_state()
    context.collect_ufw_state()

    hardening_actions: List[str] = []
    if apply_hardening:
        hardening_actions.extend(context.apply_firewalld_hardening())
        hardening_actions.extend(context.apply_ufw_hardening())

    export_path = context.save_export()
    report_path = context.generate_report()
    summary = context.build_summary()

    message_parts = ["Firewall configuration exported"]
    if apply_hardening:
        if dry_run:
            message_parts.append("(preview mode – no changes applied)")
        else:
            message_parts.append("and hardening applied")
    if export_path:
        message_parts.append(f"export file: {export_path}")
    if report_path:
        message_parts.append(f"report: {report_path}")

    return {
        "success": True,
        "message": "; ".join(message_parts),
        "summary": summary,
        "export_file": str(export_path) if export_path else None,
        "report_file": str(report_path) if report_path else None,
        "hardening_actions": hardening_actions,
        "data": context.export_data,
    }


def get_firewall_summary() -> str:
    """Return a human readable summary of current firewall state."""
    result = export_firewall_security(dry_run=True, apply_hardening=False)
    return result["summary"]


def preview_firewall_hardening() -> str:
    """Return the actions that would be taken during firewall hardening."""
    result = export_firewall_security(dry_run=True, apply_hardening=True)
    actions = result.get("hardening_actions", [])
    if not actions:
        return "No firewall hardening actions are required."
    return "\n".join(actions)


def apply_firewall_hardening(dry_run: bool = False) -> Dict[str, Any]:
    """Apply firewall hardening and return the result dictionary."""
    return export_firewall_security(dry_run=dry_run, apply_hardening=True)
