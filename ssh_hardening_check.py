"""
SSH Security Hardening Check

Functions:
- verify_ssh_hardening(): returns (ok, message) for current SSH security status
- harden_ssh_config(): applies SSH security hardening (destructive)

This module extends the existing ssh_check with hardening capabilities.
"""

import os
import subprocess
from typing import Tuple, Dict, Any


def _run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Execute a shell command safely"""
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)


def check_ssh_hardening_status() -> Dict[str, Any]:
    """
    Check current SSH hardening status
    
    Returns:
        Dict with current SSH security configuration status
    """
    status = {
        'ssh_service': {'running': False, 'enabled': False},
        'config_files': {},
        'security_issues': [],
        'hardened': False
    }
    
    # Check SSH service status
    try:
        result = _run_command(['systemctl', 'is-active', 'ssh'], check=False)
        status['ssh_service']['running'] = result.returncode == 0
        
        result = _run_command(['systemctl', 'is-enabled', 'ssh'], check=False)
        status['ssh_service']['enabled'] = result.returncode == 0
    except Exception:
        pass
    
    # Check for hardening config file
    hardening_config = '/etc/ssh/sshd_config.d/99-security-hardening.conf'
    status['config_files'][hardening_config] = os.path.exists(hardening_config)
    
    # Check main SSH config for security issues
    main_config = '/etc/ssh/sshd_config'
    if os.path.exists(main_config):
        status['config_files'][main_config] = True
        try:
            with open(main_config, 'r') as f:
                config_content = f.read()
                
            # Check for common security issues
            if 'PermitRootLogin yes' in config_content:
                status['security_issues'].append('Root login is enabled')
            if 'PasswordAuthentication yes' in config_content:
                status['security_issues'].append('Password authentication is enabled')
            if 'Port 22' in config_content or config_content.count('Port') == 0:
                status['security_issues'].append('Using default SSH port (22)')
            if 'X11Forwarding yes' in config_content:
                status['security_issues'].append('X11 forwarding is enabled')
                
        except Exception as e:
            status['security_issues'].append(f'Could not read SSH config: {e}')
    else:
        status['config_files'][main_config] = False
        status['security_issues'].append('Main SSH config file not found')
    
    # Determine if SSH is hardened
    status['hardened'] = (
        len(status['security_issues']) == 0 and
        status['config_files'].get(hardening_config, False)
    )
    
    return status


def verify_ssh_hardening() -> Tuple[bool, str]:
    """
    Verify SSH hardening status (non-destructive)
    
    Returns:
        Tuple of (is_hardened, status_message)
    """
    status = check_ssh_hardening_status()
    
    if status['hardened']:
        return True, "SSH is properly hardened with security configuration"
    
    issues = status['security_issues']
    if not issues:
        issues = ['SSH hardening configuration not detected']
    
    message = f"SSH security issues found: {', '.join(issues)}"
    return False, message


def apply_ssh_hardening(dry_run: bool = False) -> Tuple[bool, str]:
    """
    Apply SSH security hardening (destructive)
    
    Args:
        dry_run: If True, only show what would be done
        
    Returns:
        Tuple of (success, message)
    """
    try:
        # Import here to avoid circular import
        from .security_hardening import harden_ssh as _harden_ssh
        result = _harden_ssh(dry_run=dry_run)
        return result['success'], result['message']
    except Exception as e:
        return False, f"SSH hardening failed: {e}"


def get_ssh_hardening_summary() -> str:
    """
    Get a summary of SSH hardening status
    
    Returns:
        Formatted string with SSH security status
    """
    status = check_ssh_hardening_status()
    
    summary = ["SSH Security Status:"]
    summary.append(f"  Service running: {status['ssh_service']['running']}")
    summary.append(f"  Service enabled: {status['ssh_service']['enabled']}")
    summary.append(f"  Hardened: {'Yes' if status['hardened'] else 'No'}")
    
    if status['security_issues']:
        summary.append("  Security Issues:")
        for issue in status['security_issues']:
            summary.append(f"    - {issue}")
    
    config_files = status['config_files']
    summary.append("  Configuration Files:")
    for path, exists in config_files.items():
        summary.append(f"    {path}: {'Found' if exists else 'Missing'}")
    
    return "\n".join(summary)