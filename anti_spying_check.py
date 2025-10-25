"""
Anti-Spying Services Security Check

Functions:
- verify_anti_spying(): returns (ok, message) for current anti-spying status
- apply_anti_spying_hardening(): applies comprehensive anti-spying measures (destructive)

This module provides comprehensive protection against services that could be used for spying
on an infected system, including SSH, remote desktop, video casting, streaming, and more.
"""

import os
import subprocess
from typing import Tuple, Dict, List, Any
from pathlib import Path


def _run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Execute a shell command safely"""
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)


def check_spying_services_status() -> Dict[str, Any]:
    """
    Check status of services that could be used for spying
    
    Returns:
        Dict with comprehensive spying service analysis
    """
    status = {
        'remote_access': {},
        'remote_desktop': {},
        'screen_sharing': {},
        'file_sharing': {},
        'discovery': {},
        'communication_apps': {},
        'audio_devices': {},
        'blocked_ports': [],
        'security_issues': []
    }
    
    # Remote access services
    remote_services = ['ssh', 'sshd', 'telnet', 'rsh', 'rlogin']
    for service in remote_services:
        service_info = {'running': False, 'enabled': False, 'masked': False}
        try:
            result = _run_command(['systemctl', 'is-active', service], check=False)
            service_info['running'] = result.returncode == 0
            
            result = _run_command(['systemctl', 'is-enabled', service], check=False)
            service_info['enabled'] = result.returncode == 0
            
            result = _run_command(['systemctl', 'status', service], check=False)
            service_info['masked'] = 'masked' in result.stdout
            
            if service_info['running'] or service_info['enabled']:
                status['security_issues'].append(f'Remote access service active: {service}')
                
        except Exception:
            pass
        
        status['remote_access'][service] = service_info
    
    # Remote desktop services
    desktop_services = ['xrdp', 'vncserver', 'tightvncserver', 'x11vnc']
    for service in desktop_services:
        service_info = {'running': False, 'enabled': False, 'masked': False}
        try:
            result = _run_command(['systemctl', 'is-active', service], check=False)
            service_info['running'] = result.returncode == 0
            
            result = _run_command(['systemctl', 'is-enabled', service], check=False)
            service_info['enabled'] = result.returncode == 0
            
            result = _run_command(['systemctl', 'status', service], check=False)
            service_info['masked'] = 'masked' in result.stdout
            
            if service_info['running'] or service_info['enabled']:
                status['security_issues'].append(f'Remote desktop service active: {service}')
                
        except Exception:
            pass
        
        status['remote_desktop'][service] = service_info
    
    # Screen sharing services
    screen_services = ['gnome-remote-desktop', 'vino', 'miracast']
    for service in screen_services:
        service_info = {'running': False, 'enabled': False}
        try:
            result = _run_command(['systemctl', 'is-active', service], check=False)
            service_info['running'] = result.returncode == 0
            
            if service_info['running']:
                status['security_issues'].append(f'Screen sharing active: {service}')
                
        except Exception:
            pass
        
        status['screen_sharing'][service] = service_info
    
    # File sharing services
    file_services = ['smbd', 'nmbd', 'nfs-server', 'ftpd', 'vsftpd']
    for service in file_services:
        service_info = {'running': False, 'enabled': False, 'masked': False}
        try:
            result = _run_command(['systemctl', 'is-active', service], check=False)
            service_info['running'] = result.returncode == 0
            
            result = _run_command(['systemctl', 'is-enabled', service], check=False)
            service_info['enabled'] = result.returncode == 0
            
            if service_info['running'] or service_info['enabled']:
                status['security_issues'].append(f'File sharing service active: {service}')
                
        except Exception:
            pass
        
        status['file_sharing'][service] = service_info
    
    # Network discovery services
    discovery_services = ['avahi-daemon', 'bonjour', 'upnp']
    for service in discovery_services:
        service_info = {'running': False, 'enabled': False}
        try:
            result = _run_command(['systemctl', 'is-active', service], check=False)
            service_info['running'] = result.returncode == 0
            
            if service_info['running']:
                status['security_issues'].append(f'Network discovery active: {service}')
                
        except Exception:
            pass
        
        status['discovery'][service] = service_info
    
    # Communication / streaming apps (Telegram and related tooling)
    communication_targets = {
        'telegram-desktop': 'Telegram Desktop',
        'tdesktop': 'Telegram Desktop',
        'telegram-cli': 'Telegram CLI',
        'telegram': 'Telegram process',
        'mtproto-proxy': 'MTProto proxy',
        'zoom': 'Zoom conferencing',
        'zoom-real-time': 'Zoom conferencing',
        'skypeforlinux': 'Skype client',
        'skype': 'Skype client',
        'teams': 'Microsoft Teams',
        'msteams': 'Microsoft Teams',
        'teams-for-linux': 'Microsoft Teams (Linux)',
        'discord': 'Discord client',
        'slack': 'Slack client',
        'signal-desktop': 'Signal Desktop',
        'signal': 'Signal messenger',
        'element-desktop': 'Matrix Element client',
        'obs64': 'OBS Studio streaming',
        'obs': 'OBS Studio streaming',
        'vokoscreen': 'Vokoscreen recorder',
        'webex': 'Cisco Webex client',
        'zoomvdi': 'Zoom VDI client',
        'anydesk': 'AnyDesk remote access',
        'rustdesk': 'RustDesk remote access'
    }

    for process_name, label in communication_targets.items():
        try:
            result = _run_command(['pgrep', '-f', process_name], check=False)
            is_running = result.returncode == 0
            status['communication_apps'][label] = {
                'running': is_running,
                'process_name': process_name
            }
            if is_running:
                issue = f'Communication/streaming component detected: {label}'
                if issue not in status['security_issues']:
                    status['security_issues'].append(issue)
        except Exception:
            status['communication_apps'][label] = {'running': False, 'process_name': process_name}

    # Audio devices security
    audio_devices = list(Path('/dev/snd').glob('*')) if Path('/dev/snd').exists() else []
    status['audio_devices']['count'] = len(audio_devices)
    status['audio_devices']['secured'] = False
    
    if audio_devices:
        try:
            # Check if audio devices have restrictive permissions
            for device in audio_devices[:3]:  # Check first few devices
                stat_info = device.stat()
                if oct(stat_info.st_mode)[-3:] == '600':
                    status['audio_devices']['secured'] = True
                    break
        except Exception:
            pass
        
        if not status['audio_devices']['secured']:
            status['security_issues'].append('Audio devices not secured against eavesdropping')
    
    # Check firewall status for spying ports
    try:
        result = _run_command(['sudo', 'ufw', 'status', 'numbered'], check=False)
        ufw_output = result.stdout
        
        spying_ports = ['22', '23', '3389', '5900', '445', '139', '8080', '8554']
        blocked_count = 0
        
        for port in spying_ports:
            if f'DENY IN' in ufw_output and port in ufw_output:
                blocked_count += 1
                status['blocked_ports'].append(port)
        
        if blocked_count < len(spying_ports) // 2:
            status['security_issues'].append('Insufficient firewall protection against spying ports')
            
    except Exception:
        status['security_issues'].append('Cannot verify firewall status')
    
    return status


def verify_anti_spying() -> Tuple[bool, str]:
    """
    Verify anti-spying protections are in place (non-destructive)
    
    Returns:
        Tuple of (is_protected, status_message)
    """
    status = check_spying_services_status()
    
    if not status['security_issues']:
        return True, "System is protected against spying services"
    
    # Count active threats
    active_remote = sum(1 for info in status['remote_access'].values() 
                       if info['running'] or info['enabled'])
    active_desktop = sum(1 for info in status['remote_desktop'].values() 
                        if info['running'] or info['enabled'])
    active_sharing = sum(1 for info in status['file_sharing'].values() 
                        if info['running'] or info['enabled'])
    active_comm = any(info.get('running') for info in status['communication_apps'].values())
    
    threat_level = "LOW"
    if active_remote > 0:
        threat_level = "HIGH"
    elif active_desktop > 0 or active_sharing > 1 or active_comm:
        threat_level = "MEDIUM"
    
    message = f"Anti-spying protection: {threat_level} RISK - {len(status['security_issues'])} issues found"
    return False, message


def apply_anti_spying_hardening(dry_run: bool = False) -> Tuple[bool, str]:
    """
    Apply comprehensive anti-spying hardening (destructive)
    
    Args:
        dry_run: If True, only show what would be done
        
    Returns:
        Tuple of (success, message)
    """
    try:
        # Import here to avoid circular import
        from .security_hardening import disable_spying_services as _disable_spying_services
        result = _disable_spying_services(dry_run=dry_run)
        return result['success'], result['message']
    except Exception as e:
        return False, f"Anti-spying hardening failed: {e}"


def get_anti_spying_summary() -> str:
    """
    Get a comprehensive summary of anti-spying protection status
    
    Returns:
        Formatted string with anti-spying status
    """
    status = check_spying_services_status()
    
    summary = ["Anti-Spying Protection Status:"]
    
    # Remote access services
    summary.append("  Remote Access Services:")
    for service, info in status['remote_access'].items():
        if info['running'] or info['enabled']:
            state = []
            if info['running']:
                state.append("RUNNING")
            if info['enabled']:
                state.append("ENABLED")
            if info['masked']:
                state.append("masked")
            summary.append(f"    {service}: {' + '.join(state)} ⚠️")
        else:
            summary.append(f"    {service}: disabled ✓")
    
    # Remote desktop services  
    summary.append("  Remote Desktop Services:")
    for service, info in status['remote_desktop'].items():
        if info['running'] or info['enabled']:
            state = []
            if info['running']:
                state.append("RUNNING")
            if info['enabled']:
                state.append("ENABLED")
            summary.append(f"    {service}: {' + '.join(state)} ⚠️")
        else:
            summary.append(f"    {service}: disabled ✓")
    
    # File sharing services
    summary.append("  File Sharing Services:")
    for service, info in status['file_sharing'].items():
        if info['running'] or info['enabled']:
            state = []
            if info['running']:
                state.append("RUNNING")
            if info['enabled']:
                state.append("ENABLED")
            summary.append(f"    {service}: {' + '.join(state)} ⚠️")
        else:
            summary.append(f"    {service}: disabled ✓")
    
    # Communication / streaming applications
    summary.append("  Communication / Streaming Apps:")
    for label, info in status['communication_apps'].items():
        if info.get('running'):
            summary.append(f"    {label}: RUNNING ⚠️ (process: {info.get('process_name')})")
        else:
            summary.append(f"    {label}: not running ✓")

    # Audio security
    summary.append("  Audio Device Security:")
    summary.append(f"    Audio devices found: {status['audio_devices']['count']}")
    audio_status = "secured ✓" if status['audio_devices']['secured'] else "unsecured ⚠️"
    summary.append(f"    Audio protection: {audio_status}")
    
    # Firewall protection
    summary.append("  Firewall Protection:")
    summary.append(f"    Blocked spying ports: {len(status['blocked_ports'])}")
    if status['blocked_ports']:
        summary.append(f"    Ports blocked: {', '.join(status['blocked_ports'][:8])}")
    
    # Security issues summary
    if status['security_issues']:
        summary.append("  ⚠️  Security Issues:")
        for issue in status['security_issues'][:5]:
            summary.append(f"    - {issue}")
        if len(status['security_issues']) > 5:
            summary.append(f"    ... and {len(status['security_issues'])-5} more")
    else:
        summary.append("  ✓ No security issues detected")
    
    return "\n".join(summary)