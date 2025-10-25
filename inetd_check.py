"""inetd/xinetd security checks and hardening helpers."""

import os
from typing import List, Tuple

def is_inetd_installed():
    return any(os.path.exists(path) for path in ["/usr/sbin/inetd", "/usr/sbin/xinetd"])

def check_inetd_status():
    results = {}
    for service in ["inetd", "xinetd"]:
        service_path = f"/usr/sbin/{service}"
        if os.path.exists(service_path):
            # Check if running
            running = os.system(f"pgrep {service} > /dev/null") == 0
            # Check if enabled at boot (systemd)
            enabled = os.system(f"systemctl is-enabled {service} > /dev/null 2>&1") == 0
            results[service] = {"installed": True, "running": running, "enabled": enabled}
        else:
            results[service] = {"installed": False, "running": False, "enabled": False}
    return results

def secure_inetd_configs():
    # Example: check for world-writable config files
    findings = []
    for conf in ["/etc/inetd.conf", "/etc/xinetd.conf"]:
        if os.path.exists(conf):
            perms = oct(os.stat(conf).st_mode)[-3:]
            if perms != "600":
                findings.append(f"{conf} permissions are {perms}, should be 600.")
    return findings


def get_inetd_summary() -> str:
    """Return a human-readable summary of inetd/xinetd status."""
    status = check_inetd_status()
    findings = secure_inetd_configs()

    lines: List[str] = ["inetd/xinetd status summary:"]
    for service, info in status.items():
        state_parts: List[str] = []
        if info["installed"]:
            state_parts.append("installed")
            if info["running"]:
                state_parts.append("running")
            if info["enabled"]:
                state_parts.append("enabled")
            if not state_parts or (len(state_parts) == 1 and state_parts[0] == "installed"):
                state_parts.append("inactive")
        else:
            state_parts.append("not present")
        lines.append(f"  - {service}: {', '.join(state_parts)}")

    if findings:
        lines.append("Configuration findings:")
        lines.extend(f"  * {finding}" for finding in findings)
    else:
        lines.append("Configuration files already restricted (mode 600).")

    return "\n".join(lines)


def verify_inetd_security() -> Tuple[bool, str]:
    """Return whether inetd/xinetd appear secured."""
    status = check_inetd_status()
    findings: List[str] = []

    for service, info in status.items():
        if info["installed"] and (info["running"] or info["enabled"]):
            findings.append(f"{service} is {'running' if info['running'] else 'enabled'}")

    if secure_inetd_configs():
        findings.append("Configuration files have permissive permissions.")

    if findings:
        return False, "inetd/xinetd issues detected: " + "; ".join(findings)
    return True, "inetd and xinetd appear disabled and configuration files are restricted."


def apply_inetd_hardening(dry_run: bool = False) -> Tuple[bool, str]:
    """Apply inetd/xinetd hardening via the shared hardening module."""
    try:
        # Import here to avoid circular import
        from .security_hardening import disable_inetd_services as _disable_inetd_services
        result = _disable_inetd_services(dry_run=dry_run)
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"inetd/xinetd hardening failed: {exc}"

    success = result.get("success", False)
    message = result.get("message", "inetd/xinetd hardening completed")

    details: List[str] = []
    for detail in result.get("details", []):
        service = detail.get("service", "inetd/xinetd")
        status = "ok" if detail.get("success", False) else "failed"
        actions = detail.get("actions", [])
        joined_actions = "; ".join(actions) if actions else "no changes"
        details.append(f"{service}: {status} ({joined_actions})")

    if details:
        message = message + "\n" + "\n".join(details)

    return success, message
