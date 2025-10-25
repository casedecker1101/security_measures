"""
SMB/Samba Security Hardening Check

Functions:
- verify_smb_security(): returns (ok, message) for current SMB security status
- apply_smb_hardening(): applies SMB security hardening (destructive)

This module provides SMB/Samba security checking and hardening capabilities.
"""

import os
import subprocess
from typing import Tuple, Dict, List, Any


def _run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Execute a shell command safely"""
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)


def check_smb_services() -> Dict[str, Dict[str, bool]]:
    """
    Check SMB/Samba service status
    
    Returns:
        Dict with service status information
    """
    services = ['smbd', 'nmbd', 'samba']
    status = {}
    
    for service in services:
        service_info = {'installed': False, 'running': False, 'enabled': False, 'masked': False}
        
        try:
            # Check if service exists
            result = _run_command(['systemctl', 'list-unit-files', service], check=False)
            service_info['installed'] = service in result.stdout
            
            if service_info['installed']:
                # Check if running
                result = _run_command(['systemctl', 'is-active', service], check=False)
                service_info['running'] = result.returncode == 0
                
                # Check if enabled
                result = _run_command(['systemctl', 'is-enabled', service], check=False)
                service_info['enabled'] = result.returncode == 0
                
                # Check if masked
                service_info['masked'] = 'masked' in result.stdout
                
        except Exception:
            pass
            
        status[service] = service_info
    
    return status


def check_smb_ports() -> Dict[str, bool]:
    """
    Check if SMB ports are blocked by firewall
    
    Returns:
        Dict with port blocking status
    """
    smb_ports = ['445', '139', '137', '138']
    port_status = {}
    
    try:
        # Check UFW status
        result = _run_command(['sudo', 'ufw', 'status', 'numbered'], check=False)
        ufw_output = result.stdout
        
        for port in smb_ports:
            # Look for deny rules for this port
            port_blocked = f'DENY IN' in ufw_output and port in ufw_output
            port_status[port] = port_blocked
            
    except Exception:
        # If UFW check fails, assume ports are not blocked
        for port in smb_ports:
            port_status[port] = False
    
    return port_status


def check_smb_config() -> Dict[str, Any]:
    """
    Check SMB configuration security
    
    Returns:
        Dict with configuration analysis
    """
    config_path = '/etc/samba/smb.conf'
    config_info = {
        'exists': False,
        'backup_exists': False,
        'security_issues': [],
        'hardened': False
    }
    
    config_info['exists'] = os.path.exists(config_path)
    config_info['backup_exists'] = os.path.exists(f'{config_path}.backup')
    
    if config_info['exists']:
        try:
            with open(config_path, 'r') as f:
                content = f.read()
            
            # Check for security issues
            if 'guest ok = yes' in content.lower():
                config_info['security_issues'].append('Guest access enabled')
            if 'map to guest = bad user' in content.lower():
                config_info['security_issues'].append('Bad user mapping to guest')
            if 'security = share' in content.lower():
                config_info['security_issues'].append('Share-level security (weak)')
            if 'encrypt passwords = no' in content.lower():
                config_info['security_issues'].append('Password encryption disabled')
            
            # Check if it's our hardened config
            if 'Services are masked to prevent accidental startup' in content:
                config_info['hardened'] = True
                
        except Exception as e:
            config_info['security_issues'].append(f'Could not read config: {e}')
    
    return config_info


def verify_smb_security() -> Tuple[bool, str]:
    """
    Verify SMB security status (non-destructive)
    
    Returns:
        Tuple of (is_secure, status_message)
    """
    services = check_smb_services()
    ports = check_smb_ports()
    config = check_smb_config()
    
    issues = []
    
    # Check if any SMB services are running
    running_services = [svc for svc, info in services.items() if info['running']]
    if running_services:
        issues.append(f"SMB services running: {', '.join(running_services)}")
    
    # Check if any SMB services are enabled
    enabled_services = [svc for svc, info in services.items() if info['enabled']]
    if enabled_services:
        issues.append(f"SMB services enabled: {', '.join(enabled_services)}")
    
    # Check if ports are not blocked
    open_ports = [port for port, blocked in ports.items() if not blocked]
    if open_ports:
        issues.append(f"SMB ports not blocked: {', '.join(open_ports)}")
    
    # Check configuration issues
    if config['security_issues']:
        issues.extend(config['security_issues'])
    
    # Check if properly hardened
    all_masked = all(info.get('masked', False) for info in services.values() if info['installed'])
    all_ports_blocked = all(ports.values())
    
    is_secure = (
        not running_services and
        not enabled_services and
        all_ports_blocked and
        len(config['security_issues']) == 0 and
        (config['hardened'] or not config['exists'])
    )
    
    if is_secure:
        return True, "SMB/Samba is properly secured and disabled"
    else:
        message = f"SMB security issues found: {', '.join(issues)}"
        return False, message


def apply_smb_hardening(dry_run: bool = False) -> Tuple[bool, str]:
    """
    Apply SMB security hardening (destructive)
    
    Args:
        dry_run: If True, only show what would be done
        
    Returns:
        Tuple of (success, message)
    """
    try:
        # Import here to avoid circular import
        from .security_hardening import secure_smb as _secure_smb
        result = _secure_smb(dry_run=dry_run)
        return result['success'], result['message']
    except Exception as e:
        return False, f"SMB hardening failed: {e}"


def get_smb_security_summary() -> str:
    """
    Get a summary of SMB security status
    
    Returns:
        Formatted string with SMB security status
    """
    services = check_smb_services()
    ports = check_smb_ports()
    config = check_smb_config()
    
    summary = ["SMB/Samba Security Status:"]
    
    # Services status
    summary.append("  Services:")
    for service, info in services.items():
        if info['installed']:
            status_parts = []
            if info['running']:
                status_parts.append("running")
            if info['enabled']:
                status_parts.append("enabled")
            if info['masked']:
                status_parts.append("masked")
            if not status_parts:
                status_parts.append("stopped/disabled")
            
            summary.append(f"    {service}: {', '.join(status_parts)}")
        else:
            summary.append(f"    {service}: not installed")
    
    # Port status
    summary.append("  Ports:")
    for port, blocked in ports.items():
        status = "blocked" if blocked else "open"
        summary.append(f"    {port}: {status}")
    
    # Configuration
    summary.append("  Configuration:")
    summary.append(f"    Config exists: {config['exists']}")
    summary.append(f"    Backup exists: {config['backup_exists']}")
    summary.append(f"    Hardened: {config['hardened']}")
    
    if config['security_issues']:
        summary.append("    Security Issues:")
        for issue in config['security_issues']:
            summary.append(f"      - {issue}")
    
    return "\n".join(summary)