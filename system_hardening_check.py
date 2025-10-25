"""
System Security Hardening Check

Functions:
- verify_system_hardening(): returns (ok, message) for overall system security status
- apply_full_hardening(): applies comprehensive system hardening (destructive)

This module provides comprehensive system security checking and hardening capabilities.
"""

import os
import subprocess
from typing import Tuple, Dict, List, Any


def _run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Execute a shell command safely"""
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)


def check_camera_devices() -> Dict[str, Any]:
    """Check camera device security status"""
    from pathlib import Path
    
    status = {
        'video_devices': [],
        'devices_disabled': False,
        'modules_blacklisted': False,
        'udev_rules_present': False
    }
    
    # Find video devices
    video_devices = list(Path('/dev').glob('video*'))
    status['video_devices'] = [str(d) for d in video_devices]
    
    # Check if devices are disabled (permissions 000)
    if video_devices:
        try:
            for device in video_devices:
                stat_info = device.stat()
                if oct(stat_info.st_mode)[-3:] == '000':
                    status['devices_disabled'] = True
                    break
        except Exception:
            pass
    
    # Check for camera module blacklist
    blacklist_file = '/etc/modprobe.d/blacklist-camera.conf'
    status['modules_blacklisted'] = os.path.exists(blacklist_file)
    
    # Check for udev rules
    udev_file = '/etc/udev/rules.d/99-disable-webcam.rules'
    status['udev_rules_present'] = os.path.exists(udev_file)
    
    return status


def check_unnecessary_services() -> Dict[str, Dict[str, bool]]:
    """Check status of unnecessary server services"""
    services = [
        'apache2', 'nginx', 'mariadb', 'mysql', 'postgresql', 
        'redis-server', 'snmpd', 'avahi-daemon', 'rpcbind', 
        'atftpd', 'tftpd-hpa'
    ]
    
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


def check_sudo_configuration() -> Dict[str, Any]:
    """Check sudo configuration for passwordless access"""
    status = {
        'sudoers_files': {},
        'passwordless_access': False,
        'backup_exists': False
    }
    
    sudoers_files = [
        '/etc/sudoers.d/kali-grant-root',
        '/etc/sudoers.d/kali-trusted'
    ]
    
    for sudoers_file in sudoers_files:
        file_info = {'exists': False, 'has_nopasswd': False}
        
        if os.path.exists(sudoers_file):
            file_info['exists'] = True
            try:
                with open(sudoers_file, 'r') as f:
                    content = f.read()
                file_info['has_nopasswd'] = 'NOPASSWD' in content
                if file_info['has_nopasswd']:
                    status['passwordless_access'] = True
            except Exception:
                pass
            
            # Check for backup
            if os.path.exists(f'{sudoers_file}.backup'):
                status['backup_exists'] = True
        
        status['sudoers_files'][sudoers_file] = file_info
    
    return status


def check_security_tools() -> Dict[str, bool]:
    """Check if security tools are installed"""
    tools = ['rkhunter', 'chkrootkit', 'fail2ban']
    status = {}
    
    for tool in tools:
        try:
            result = _run_command(['which', tool], check=False)
            status[tool] = result.returncode == 0
        except Exception:
            status[tool] = False
    
    return status


def check_network_hardening() -> Dict[str, Any]:
    """Check network hardening configurations"""
    status = {
        'sysctl_files': {},
        'rdp_vnc_blocked': False,
        'ip_forwarding_disabled': False
    }
    
    # Check sysctl hardening files
    sysctl_files = [
        '/etc/sysctl.d/99-rdp-hardening.conf'
    ]
    
    for sysctl_file in sysctl_files:
        status['sysctl_files'][sysctl_file] = os.path.exists(sysctl_file)
    
    # Check if IP forwarding is disabled
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            ip_forward = f.read().strip()
        status['ip_forwarding_disabled'] = ip_forward == '0'
    except Exception:
        pass
    
    # Check firewall rules for RDP/VNC ports
    try:
        result = _run_command(['sudo', 'ufw', 'status', 'numbered'], check=False)
        ufw_output = result.stdout
        rdp_vnc_ports = ['3389', '5900', '5901', '5902', '5903']
        
        blocked_ports = 0
        for port in rdp_vnc_ports:
            if f'DENY IN' in ufw_output and port in ufw_output:
                blocked_ports += 1
        
        status['rdp_vnc_blocked'] = blocked_ports > 0
        
    except Exception:
        pass
    
    return status


def verify_system_hardening() -> Tuple[bool, str]:
    """
    Verify overall system hardening status (non-destructive)
    
    Returns:
        Tuple of (is_hardened, status_message)
    """
    issues = []
    
    # Check cameras
    camera_status = check_camera_devices()
    if camera_status['video_devices'] and not camera_status['devices_disabled']:
        issues.append("Camera devices are not disabled")
    
    # Check unnecessary services
    services_status = check_unnecessary_services()
    running_services = [svc for svc, info in services_status.items() 
                       if info['installed'] and (info['running'] or info['enabled'])]
    if running_services:
        issues.append(f"Unnecessary services running/enabled: {', '.join(running_services[:3])}")
    
    # Check sudo configuration
    sudo_status = check_sudo_configuration()
    if sudo_status['passwordless_access']:
        issues.append("Passwordless sudo access detected")
    
    # Check security tools
    tools_status = check_security_tools()
    missing_tools = [tool for tool, installed in tools_status.items() if not installed]
    if missing_tools:
        issues.append(f"Security tools not installed: {', '.join(missing_tools)}")
    
    # Check network hardening
    network_status = check_network_hardening()
    if not network_status['ip_forwarding_disabled']:
        issues.append("IP forwarding is enabled")
    if not network_status['rdp_vnc_blocked']:
        issues.append("RDP/VNC ports not blocked")
    
    is_hardened = len(issues) == 0
    
    if is_hardened:
        return True, "System is properly hardened"
    else:
        message = f"System hardening issues: {', '.join(issues[:5])}"
        if len(issues) > 5:
            message += f" (and {len(issues)-5} more)"
        return False, message


def apply_full_hardening(dry_run: bool = False) -> Tuple[bool, str]:
    """
    Apply comprehensive system hardening (destructive)
    
    Args:
        dry_run: If True, only show what would be done
        
    Returns:
        Tuple of (success, message)
    """
    try:
        # Import here to avoid circular import
        from .security_hardening import SecurityHardening
        hardening = SecurityHardening(dry_run=dry_run)
        result = hardening.run_full_hardening()
        return result['success'], result['message']
    except Exception as e:
        return False, f"System hardening failed: {e}"


def get_system_hardening_summary() -> str:
    """
    Get a comprehensive summary of system hardening status
    
    Returns:
        Formatted string with system security status
    """
    summary = ["System Security Hardening Status:"]
    
    # Camera devices
    camera_status = check_camera_devices()
    summary.append("  Camera Devices:")
    summary.append(f"    Video devices found: {len(camera_status['video_devices'])}")
    summary.append(f"    Devices disabled: {camera_status['devices_disabled']}")
    summary.append(f"    Modules blacklisted: {camera_status['modules_blacklisted']}")
    summary.append(f"    Udev rules present: {camera_status['udev_rules_present']}")
    
    # Unnecessary services
    services_status = check_unnecessary_services()
    summary.append("  Unnecessary Services:")
    running_count = sum(1 for info in services_status.values() if info['running'])
    enabled_count = sum(1 for info in services_status.values() if info['enabled'])
    masked_count = sum(1 for info in services_status.values() if info['masked'])
    summary.append(f"    Running: {running_count}")
    summary.append(f"    Enabled: {enabled_count}")
    summary.append(f"    Masked: {masked_count}")
    
    # Sudo configuration
    sudo_status = check_sudo_configuration()
    summary.append("  Sudo Configuration:")
    summary.append(f"    Passwordless access: {sudo_status['passwordless_access']}")
    summary.append(f"    Backup exists: {sudo_status['backup_exists']}")
    
    # Security tools
    tools_status = check_security_tools()
    summary.append("  Security Tools:")
    for tool, installed in tools_status.items():
        summary.append(f"    {tool}: {'installed' if installed else 'not installed'}")
    
    # Network hardening
    network_status = check_network_hardening()
    summary.append("  Network Hardening:")
    summary.append(f"    IP forwarding disabled: {network_status['ip_forwarding_disabled']}")
    summary.append(f"    RDP/VNC blocked: {network_status['rdp_vnc_blocked']}")
    
    return "\n".join(summary)