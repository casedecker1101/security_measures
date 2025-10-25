"""
SSH hardening checks

Functions:
- check_ssh_status(): returns a dict with service and config findings
- verify_ssh_hardening(): returns (ok, message) summarizing the checks

This module is conservative and non-destructive: it only reads config files
and queries systemctl where available.
"""
import os
import re
import subprocess
from typing import Tuple, Dict, List


def _has_systemctl() -> bool:
    return os.path.exists("/bin/systemctl") or os.path.exists("/usr/bin/systemctl")


def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _check_service(name: str) -> Dict[str, object]:
    info = {"installed": False, "running": False, "enabled": False, "name": name}
    if _has_systemctl():
        # Check active
        res_active = _run(["systemctl", "is-active", name])
        info["installed"] = (res_active.returncode == 0) or (res_active.returncode == 3)
        info["running"] = (res_active.returncode == 0)
        # Check enabled
        res_enabled = _run(["systemctl", "is-enabled", name])
        info["enabled"] = (res_enabled.returncode == 0)
    else:
        # Fallback: look for typical init script or binary
        info["installed"] = os.path.exists(f"/etc/init.d/{name}") or os.path.exists(f"/usr/sbin/{name}")
        info["running"] = False
        info["enabled"] = False
    return info


def _parse_sshd_config(path: str = "/etc/ssh/sshd_config") -> Dict[str, object]:
    result = {"path": path, "exists": False, "permit_root_login": None, "ports": []}
    if not os.path.exists(path):
        return result
    result["exists"] = True
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # collapse internal whitespace
                parts = re.split(r"\s+", line, maxsplit=1)
                key = parts[0].lower()
                val = parts[1].strip() if len(parts) > 1 else ""
                if key == "permitrootlogin":
                    result["permit_root_login"] = val.lower()
                if key == "port":
                    # support multiple Port directives
                    try:
                        result["ports"].append(int(val))
                    except ValueError:
                        pass
    except Exception:
        pass
    return result


def check_ssh_status() -> Dict[str, object]:
    """Return a detailed dict describing SSH service and config state."""
    # Prefer service name 'sshd' then 'ssh'
    svc = _check_service("sshd")
    if not svc["installed"]:
        svc = _check_service("ssh")

    cfg = _parse_sshd_config()

    return {"service": svc, "config": cfg}


def verify_ssh_hardening() -> Tuple[bool, str]:
    """Verify three things:
    - SSH service is disabled or not running
    - PermitRootLogin is set to 'no'
    - Port is changed from 22 (if explicitly set)

    Returns (ok, message). ok is True only if service not running AND root login disabled.
    Port check is informational (not required to be changed to pass ok).
    """
    findings: List[str] = []
    status = check_ssh_status()
    svc = status["service"]
    cfg = status["config"]

    # Service checks
    if not svc["installed"]:
        findings.append("sshd service not detected (no systemd unit or init script found).")
        service_running = False
    else:
        if svc["running"]:
            findings.append(f"SSH service '{svc['name']}' is running.")
            service_running = True
        else:
            findings.append(f"SSH service '{svc['name']}' is not running.")
            service_running = False
        if svc["enabled"]:
            findings.append(f"SSH service '{svc['name']}' is enabled on boot.")

    # Config checks
    if not cfg["exists"]:
        findings.append(f"SSH config file {cfg['path']} not found; default behavior assumed (PermitRootLogin may be default).")
        permit_root = None
        ports = []
    else:
        permit_root = cfg.get("permit_root_login")
        ports = cfg.get("ports", [])
        if permit_root is None:
            findings.append("PermitRootLogin not explicitly set in sshd_config (default may allow root access depending on distro).")
        else:
            findings.append(f"PermitRootLogin = {permit_root}")

    # Port info
    if ports:
        findings.append(f"sshd configured Port(s): {', '.join(str(p) for p in ports)}")
        port_changed = any(p != 22 for p in ports)
        if not port_changed:
            findings.append("Configured port includes default port 22.")
    else:
        findings.append("No Port directive found in sshd_config; default port 22 is used.")
        port_changed = False

    # Final decision: ok if service not running and permit_root == 'no'
    root_disabled = (permit_root == "no")

    ok = (not service_running) and root_disabled

    summary = "\n".join(findings)
    if ok:
        summary = "SSH appears hardened: service not running and root login disabled.\n" + summary
    else:
        summary = "SSH hardening issues detected:\n" + summary

    return ok, summary


if __name__ == "__main__":
    ok, msg = verify_ssh_hardening()
    print(msg)
