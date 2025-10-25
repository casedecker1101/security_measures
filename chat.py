# flatline_dixie/chat.py

import os
from typing import Dict, List, Any, Optional, cast

def _safe_get_str(d: Dict[str, Any], key: str, default: str = '') -> str:
    """Safely get a string value from a dictionary."""
    value = d.get(key, default)
    return str(value) if value is not None else default

def _safe_get_list(d: Dict[str, Any], key: str, default: Optional[List[Any]] = None) -> List[Any]:
    """Safely get a list value from a dictionary."""
    if default is None:
        default = []
    value = d.get(key, default)
    return value if isinstance(value, list) else default

def handle_input(user_input):
    if user_input.lower() == "help":
        return """Available commands:
Basic checks: check_inetd, check_hybrid_crypto, check_init, check_ssh, audit_accounts
Security hardening: check_ssh_hardening, check_smb_hardening, check_system_hardening
Anti-spying: check_anti_spying, disable_spying_services, anti_spying_summary
Firewall security: firewall_summary, firewall_export, harden_firewall
Hardening actions: harden_ssh, harden_smb, harden_system, harden_inetd, harden_remote_apps, harden_loopback, cleanup_accounts, remediate_rootkits, harden_all
Security scans: scan_rootkits, verify_boot, install_security_tools
Summaries: accounts_summary
Other: help, exit"""
    if user_input.lower() == "check_init":
        from flatline_dixie.checks import init_check
        ok, msg = init_check.verify_init_integrity()
        return msg
    if user_input.lower() == "check_inetd":
        from flatline_dixie.checks import inetd_check
        status = inetd_check.check_inetd_status()
        findings = inetd_check.secure_inetd_configs()
        response = []
        for svc, info in status.items():
            response.append(f"{svc}: installed={info['installed']}, running={info['running']}, enabled={info['enabled']}")
        if findings:
            response.append("Config findings:")
            response.extend(findings)
        else:
            response.append("No config permission issues found.")
        return "\n".join(response)
    if user_input.lower() == "check_hybrid_crypto":
        if is_hybrid_crypto_ready():
            return "Hybrid cryptography readiness detected: Post-Quantum Cryptography, Quantum Key Distribution, Zero Trust Architecture, Cryptoagility."
        else:
            return "Hybrid cryptography not fully configured. Please ensure all four requirements are met."
    if user_input.lower() == "check_ssh":
        from flatline_dixie.checks import ssh_check
        ok, msg = ssh_check.verify_ssh_hardening()
        return msg
    
    # Security hardening checks
    if user_input.lower() == "check_ssh_hardening":
        from flatline_dixie.checks import ssh_hardening_check
        ok, msg = ssh_hardening_check.verify_ssh_hardening()
        return msg
    if user_input.lower() == "check_smb_hardening":
        from flatline_dixie.checks import smb_hardening_check
        ok, msg = smb_hardening_check.verify_smb_security()
        return msg
    if user_input.lower() == "check_system_hardening":
        from flatline_dixie.checks import system_hardening_check
        ok, msg = system_hardening_check.verify_system_hardening()
        return msg
    if user_input.lower() == "check_anti_spying":
        from flatline_dixie.checks import anti_spying_check
        ok, msg = anti_spying_check.verify_anti_spying()
        return msg

    if user_input.lower() == "audit_accounts":
        from flatline_dixie.checks import account_security
        review = account_security.review_accounts()
        lines = ["Account audit findings:"]
        suspect_users = _safe_get_list(review, 'suspect_users')
        if suspect_users:
            lines.append("Suspect users:")
            for entry in suspect_users:
                lines.append(f"- {entry['name']} (uid={entry['uid']}, home={entry['home']}, shell={entry['shell']})")
        else:
            lines.append("No suspect users detected.")
        suspect_groups = _safe_get_list(review, 'suspect_groups')
        if suspect_groups:
            lines.append("Groups without members:")
            for entry in suspect_groups:
                lines.append(f"- {entry['name']} (gid={entry['gid']})")
        else:
            lines.append("No empty privileged groups detected.")
        suspicious_symlinks = _safe_get_list(review, 'suspicious_symlinks')
        if suspicious_symlinks:
            lines.append("Suspicious symlinks:")
            for entry in suspicious_symlinks:
                reason = ", ".join(str(r) for r in entry.get('reasons', []))
                lines.append(f"- {entry['path']} -> {entry['target']} ({reason})")
        else:
            lines.append("No suspicious symlinks detected.")
        return "\n".join(lines)
    
    # Hardening actions (require confirmation)
    if user_input.lower() == "harden_ssh":
        return "SSH hardening will modify system configuration. Type 'confirm_harden_ssh' to proceed or 'preview_harden_ssh' to see what would be changed."
    if user_input.lower() == "preview_harden_ssh":
        from flatline_dixie.checks import ssh_hardening_check
        success, msg = ssh_hardening_check.apply_ssh_hardening(dry_run=True)
        return f"SSH hardening preview:\n{msg}"
    if user_input.lower() == "confirm_harden_ssh":
        from flatline_dixie.checks import ssh_hardening_check
        success, msg = ssh_hardening_check.apply_ssh_hardening(dry_run=False)
        return f"SSH hardening {'completed' if success else 'failed'}: {msg}"
    
    if user_input.lower() == "harden_smb":
        return "SMB hardening will modify system configuration. Type 'confirm_harden_smb' to proceed or 'preview_harden_smb' to see what would be changed."
    if user_input.lower() == "preview_harden_smb":
        from flatline_dixie.checks import smb_hardening_check
        success, msg = smb_hardening_check.apply_smb_hardening(dry_run=True)
        return f"SMB hardening preview:\n{msg}"
    if user_input.lower() == "confirm_harden_smb":
        from flatline_dixie.checks import smb_hardening_check
        success, msg = smb_hardening_check.apply_smb_hardening(dry_run=False)
        return f"SMB hardening {'completed' if success else 'failed'}: {msg}"
    
    if user_input.lower() == "harden_system":
        return "Full system hardening will make extensive changes. Type 'confirm_harden_system' to proceed or 'preview_harden_system' to see what would be changed."
    if user_input.lower() == "preview_harden_system":
        from flatline_dixie.checks import system_hardening_check
        success, msg = system_hardening_check.apply_full_hardening(dry_run=True)
        return f"System hardening preview:\n{msg}"
    if user_input.lower() == "confirm_harden_system":
        from flatline_dixie.checks import system_hardening_check
        success, msg = system_hardening_check.apply_full_hardening(dry_run=False)
        return f"System hardening {'completed' if success else 'failed'}: {msg}"

    if user_input.lower() == "harden_inetd":
        return "inetd/xinetd hardening will disable legacy super-server daemons. Type 'confirm_harden_inetd' to proceed or 'preview_harden_inetd' to see what would be changed."
    if user_input.lower() == "preview_harden_inetd":
        from flatline_dixie.checks import inetd_check
        success, msg = inetd_check.apply_inetd_hardening(dry_run=True)
        return f"inetd hardening preview:\n{msg}"
    if user_input.lower() == "confirm_harden_inetd":
        from flatline_dixie.checks import inetd_check
        success, msg = inetd_check.apply_inetd_hardening(dry_run=False)
        return f"inetd hardening {'completed' if success else 'failed'}: {msg}"

    if user_input.lower() == "harden_remote_apps":
        return "Remote application blocking will apply firewall rules to deny remote-access and streaming services. Type 'confirm_harden_remote_apps' to proceed or 'preview_harden_remote_apps' to see what would be changed."
    if user_input.lower() == "preview_harden_remote_apps":
        from flatline_dixie.checks import block_remote_apps
        return block_remote_apps.preview_remote_app_block()
    if user_input.lower() == "confirm_harden_remote_apps":
        from flatline_dixie.checks import block_remote_apps
        result = block_remote_apps.apply_remote_app_block(dry_run=False)
        message = _safe_get_str(result, 'message', 'Remote application blocking completed')
        errors = _safe_get_list(result, 'errors')
        if errors:
            message = message + "\n" + "\n".join(f"- {err}" for err in errors)
        return message

    if user_input.lower() == "harden_loopback":
        return "Loopback restriction will drop traffic on the lo interface and 127.0.0.0/24 range. Type 'confirm_harden_loopback' to proceed or 'preview_harden_loopback' for a dry-run command list."
    if user_input.lower() == "preview_harden_loopback":
        from flatline_dixie.checks import loopback_restriction
        return loopback_restriction.preview_loopback_block()
    if user_input.lower() == "confirm_harden_loopback":
        from flatline_dixie.checks import loopback_restriction
        result = loopback_restriction.apply_loopback_block(dry_run=False)
        message = _safe_get_str(result, 'message', 'Loopback restriction applied')
        errors = _safe_get_list(result, 'errors')
        if errors:
            message = message + "\n" + "\n".join(f"- {err}" for err in errors)
        return message

    if user_input.lower() == "cleanup_accounts":
        return "Account cleanup will remove suspicious users/groups and neutralize symlinks. Type 'confirm_cleanup_accounts' to proceed or 'preview_cleanup_accounts' to review planned actions."
    if user_input.lower() == "preview_cleanup_accounts":
        from flatline_dixie.checks.security_hardening import cleanup_accounts
        result = cleanup_accounts(auto_remove=False, break_symlinks=True, dry_run=True)
        lines = [_safe_get_str(result, 'message', 'Cleanup preview')]
        review = result.get('review', {})
        if isinstance(review, dict):
            users = review.get('suspect_users', [])
            groups = review.get('suspect_groups', [])
            symlinks = review.get('suspicious_symlinks', [])
            lines.append(f"Suspect users: {len(users) if isinstance(users, list) else 0}")
            lines.append(f"Empty groups: {len(groups) if isinstance(groups, list) else 0}")
            lines.append(f"Suspicious symlinks: {len(symlinks) if isinstance(symlinks, list) else 0}")
        return "\n".join(lines)
    if user_input.lower() == "confirm_cleanup_accounts":
        from flatline_dixie.checks.security_hardening import cleanup_accounts
        result = cleanup_accounts(auto_remove=True, break_symlinks=True, dry_run=False)
        lines = [_safe_get_str(result, 'message', 'Account cleanup completed')]
        errors = _safe_get_list(result, 'errors')
        if errors:
            lines.append("Errors:")
            lines.extend(f"- {err}" for err in errors)
        return "\n".join(lines)

    if user_input.lower() == "remediate_rootkits":
        return "Rootkit remediation will remove scanner false positives, update rkhunter baselines, and lock the pulse account. Type 'confirm_remediate_rootkits' to proceed or 'preview_remediate_rootkits' to see the planned actions."
    if user_input.lower() == "preview_remediate_rootkits":
        from flatline_dixie.checks import rootkit_remediation
        preview = rootkit_remediation.run_rootkit_remediation(dry_run=True)
        lines = [_safe_get_str(preview, 'message', 'Rootkit remediation preview')]
        steps = _safe_get_list(preview, 'steps')
        for step in steps:
            action = step.get('action', 'Unknown action')
            message = step.get('message', 'No message')
            lines.append(f"- {action}: {message}")
            commands = _safe_get_list(step, 'commands')
            for cmd in commands:
                lines.append(f"    cmd: {cmd}")
        return "\n".join(lines)
    if user_input.lower() == "confirm_remediate_rootkits":
        from flatline_dixie.checks.security_hardening import remediate_rootkit_findings
        result = remediate_rootkit_findings(dry_run=False)
        lines = [_safe_get_str(result, 'message', 'Rootkit remediation completed')]
        steps = _safe_get_list(result, 'steps')
        for step in steps:
            status = 'SUCCESS' if step.get('success') else 'FAILED'
            action = step.get('action', 'Unknown action')
            message = step.get('message', 'No message')
            lines.append(f"- {action}: {status} - {message}")
            step_errors = _safe_get_list(step, 'errors')
            for err in step_errors:
                lines.append(f"    err: {err}")
        return "\n".join(lines)
    
    # Anti-spying actions
    if user_input.lower() == "disable_spying_services":
        return "Anti-spying measures will disable SSH, remote desktop, and other services. Type 'confirm_disable_spying' to proceed or 'preview_disable_spying' to see what would be changed."
    if user_input.lower() == "preview_disable_spying":
        from flatline_dixie.checks import anti_spying_check
        success, msg = anti_spying_check.apply_anti_spying_hardening(dry_run=True)
        return f"Anti-spying preview:\n{msg}"
    if user_input.lower() == "confirm_disable_spying":
        from flatline_dixie.checks import anti_spying_check
        success, msg = anti_spying_check.apply_anti_spying_hardening(dry_run=False)
        return f"Anti-spying measures {'completed' if success else 'failed'}: {msg}"
    
    # Security scanning functions
    if user_input.lower() == "scan_rootkits":
        from flatline_dixie.checks.security_hardening import scan_rootkits
        result = scan_rootkits(dry_run=False)
        return f"Rootkit scan: {result['message']}"
    
    if user_input.lower() == "verify_boot":
        from flatline_dixie.checks.security_hardening import verify_boot_partitions
        result = verify_boot_partitions(dry_run=False)
        return f"Boot verification: {result['message']}"
    
    if user_input.lower() == "install_security_tools":
        from flatline_dixie.checks.security_hardening import install_security_tools
        result = install_security_tools(dry_run=False)
        return f"Security tools installation: {result['message']}"
    
    # Summary commands
    if user_input.lower() == "ssh_summary":
        from flatline_dixie.checks import ssh_hardening_check
        return ssh_hardening_check.get_ssh_hardening_summary()
    if user_input.lower() == "smb_summary":
        from flatline_dixie.checks import smb_hardening_check
        return smb_hardening_check.get_smb_security_summary()
    if user_input.lower() == "system_summary":
        from flatline_dixie.checks import system_hardening_check
        return system_hardening_check.get_system_hardening_summary()
    if user_input.lower() == "inetd_summary":
        from flatline_dixie.checks import inetd_check
        return inetd_check.get_inetd_summary()
    if user_input.lower() == "remote_apps_summary":
        from flatline_dixie.checks import block_remote_apps
        return block_remote_apps.get_remote_app_summary()
    if user_input.lower() == "loopback_summary":
        from flatline_dixie.checks import loopback_restriction
        return loopback_restriction.get_loopback_summary()
    if user_input.lower() == "accounts_summary":
        from flatline_dixie.checks import account_security
        return account_security.get_account_security_summary()
    if user_input.lower() == "rootkit_remediation_summary":
        from flatline_dixie.checks import rootkit_remediation
        return rootkit_remediation.get_rootkit_remediation_summary()
    if user_input.lower() == "anti_spying_summary":
        from flatline_dixie.checks import anti_spying_check
        return anti_spying_check.get_anti_spying_summary()

    if user_input.lower() == "firewall_summary":
        from flatline_dixie.checks import firewall_security
        return firewall_security.get_firewall_summary()

    if user_input.lower() == "firewall_export":
        from flatline_dixie.checks import firewall_security
        result = firewall_security.export_firewall_security()
        message = _safe_get_str(result, 'message', 'Firewall configuration exported')
        report = result.get('report_file')
        export_file = result.get('export_file')
        additions = []
        if export_file:
            additions.append(f"export: {export_file}")
        if report:
            additions.append(f"report: {report}")
        if additions:
            message = f"{message}\n" + "\n".join(additions)
        return message

    if user_input.lower() == "harden_firewall":
        return "Firewall hardening will export configuration and modify firewall policies. Type 'confirm_harden_firewall' to proceed or 'preview_harden_firewall' to see what would be changed."
    if user_input.lower() == "preview_harden_firewall":
        from flatline_dixie.checks import firewall_security
        return firewall_security.preview_firewall_hardening()
    if user_input.lower() == "confirm_harden_firewall":
        from flatline_dixie.checks import firewall_security
        result = firewall_security.apply_firewall_hardening(dry_run=False)
        message = _safe_get_str(result, 'message', 'Firewall hardening completed')
        actions = _safe_get_list(result, 'hardening_actions')
        if actions:
            message = f"{message}\n" + "\n".join(f"- {action}" for action in actions)
        return message
    
    # Placeholder for future command routing
    return f"Command '{user_input}' not recognized. Type 'help' for options."

def is_hybrid_crypto_ready():
    # Placeholder: In a real system, implement actual checks for each requirement
    # For now, return False to simulate not ready, or True to simulate ready
    # Example logic (to be replaced with real checks):
    requirements = [
        os.environ.get("POST_QUANTUM_CRYPTO") == "1",
        os.environ.get("QUANTUM_KEY_DISTRIBUTION") == "1",
        os.environ.get("ZERO_TRUST_ARCHITECTURE") == "1",
        os.environ.get("CRYPTOAGILITY") == "1"
    ]
    return all(requirements)
