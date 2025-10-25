#!/usr/bin/env python3
"""
System Security Hardening Module for Flatline Dixie
Modular functions for comprehensive Linux system security hardening

This module provides the core SecurityHardening class with all hardening functions
adapted for integration with the Flatline Dixie system.
"""

import os
import subprocess
import shutil
import textwrap
from pathlib import Path
from typing import Tuple, List, Optional, Dict, Any

from flatline_dixie.checks import (
    ssh_hardening_check,
    smb_hardening_check,
    system_hardening_check,
    anti_spying_check,
    inetd_check,
    firewall_security,
    firewall_installation,
    block_remote_apps as block_remote_module,
    loopback_restriction,
    account_security,
    rootkit_remediation,
    integrated_security,
    fail2ban_hardening,
)


class SecurityHardening:
    """Class containing all security hardening functions"""
    
    def __init__(self, dry_run: bool = False):
        """
        Initialize security hardening
        
        Args:
            dry_run: If True, only show what would be done without executing
        """
        self.dry_run = dry_run
        self.results = []
    
    def _run_command(self, cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
        """
        Execute a shell command
        
        Args:
            cmd: Command and arguments as list
            check: Whether to check return code
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        if self.dry_run:
            print(f"[DRY RUN] Would execute: {' '.join(cmd)}")
            return (0, "", "")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return (result.returncode, result.stdout, result.stderr)
        except subprocess.CalledProcessError as e:
            return (e.returncode, e.stdout, e.stderr)
    
    def _write_file(self, path: str, content: str, mode: int = 0o644) -> bool:
        """
        Write content to file with sudo
        
        Args:
            path: File path
            content: Content to write
            mode: File permissions
            
        Returns:
            True if successful
        """
        if self.dry_run:
            print(f"[DRY RUN] Would write to {path}:\n{content[:100]}...")
            return True
        
        try:
            # Write to temp file first
            temp_path = f"/tmp/security_hardening_{os.path.basename(path)}"
            with open(temp_path, 'w') as f:
                f.write(content)
            
            # Move with sudo
            self._run_command(['sudo', 'cp', temp_path, path])
            self._run_command(['sudo', 'chmod', oct(mode)[2:], path])
            os.remove(temp_path)
            return True
        except Exception as e:
            print(f"Error writing {path}: {e}")
            return False
    
    def harden_ssh(self) -> dict:
        """
        Harden SSH configuration
        - Change port to 2222
        - Disable root login
        - Disable password authentication
        - Enable strong ciphers only
        - Set connection timeouts
        
        Returns:
            Dict with status and details
        """
        print("[*] Hardening SSH configuration...")
        
        ssh_config = """# SSH Security Hardening Configuration

# Change default port (reduces automated attacks)
Port 2222

# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only)
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Limit authentication attempts
MaxAuthTries 3
LoginGraceTime 30

# Use strong ciphers and algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Disable X11 forwarding
X11Forwarding no

# Enable public key authentication
PubkeyAuthentication yes

# Disconnect idle sessions
ClientAliveInterval 300
ClientAliveCountMax 2

# Limit concurrent sessions
MaxSessions 1
MaxStartups 3:50:10

# Protocol hardening
Protocol 2
HostbasedAuthentication no
IgnoreRhosts yes

# Logging
LogLevel VERBOSE
SyslogFacility AUTH
"""
        
        success = self._write_file(
            '/etc/ssh/sshd_config.d/99-security-hardening.conf',
            ssh_config
        )
        
        # Test configuration
        ret, out, err = self._run_command(['sudo', 'sshd', '-t'], check=False)
        
        return {
            'success': success and ret == 0,
            'message': 'SSH hardened successfully' if success and ret == 0 else 'SSH hardening failed',
            'config_path': '/etc/ssh/sshd_config.d/99-security-hardening.conf'
        }
    
    def disable_rdp_vnc(self) -> dict:
        """
        Disable and secure against RDP/VNC services
        - Disable VNC servers
        - Block RDP/VNC ports in firewall
        - Apply network hardening
        
        Returns:
            Dict with status and details
        """
        print("[*] Disabling RDP/VNC services...")
        
        # Disable and mask VNC services
        services = ['tightvncserver', 'vncserver', 'x11vnc']
        for service in services:
            self._run_command(['sudo', 'systemctl', 'disable', '--now', service], check=False)
            self._run_command(['sudo', 'systemctl', 'mask', service], check=False)
        
        # Block ports
        ports = [
            ('3389/tcp', 'Block RDP'),
            ('5900:5910/tcp', 'Block VNC')
        ]
        
        for port, comment in ports:
            self._run_command(['sudo', 'ufw', 'deny', port, 'comment', comment], check=False)
        
        # Network hardening sysctl
        sysctl_config = """# Network hardening against remote desktop attacks

# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP echo requests
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_all = 1
"""
        
        self._write_file('/etc/sysctl.d/99-rdp-hardening.conf', sysctl_config)
        self._run_command(['sudo', 'sysctl', '-p', '/etc/sysctl.d/99-rdp-hardening.conf'], check=False)
        
        return {
            'success': True,
            'message': 'RDP/VNC disabled and ports blocked',
            'blocked_ports': ['3389', '5900-5910']
        }
    
    def secure_smb(self) -> dict:
        """
        Secure SMB/Samba services
        - Disable and mask Samba services
        - Block SMB ports in firewall
        - Harden Samba configuration
        
        Returns:
            Dict with status and details
        """
        print("[*] Securing SMB/Samba...")
        
        # Mask services
        services = ['smbd', 'nmbd', 'samba']
        for service in services:
            self._run_command(['sudo', 'systemctl', 'disable', '--now', service], check=False)
            self._run_command(['sudo', 'systemctl', 'mask', service], check=False)
        
        # Block ports
        ports = [
            ('445/tcp', 'Block SMB'),
            ('139/tcp', 'Block NetBIOS'),
            ('137/udp', 'Block NetBIOS-NS'),
            ('138/udp', 'Block NetBIOS-DGM')
        ]
        
        for port, comment in ports:
            self._run_command(['sudo', 'ufw', 'deny', port, 'comment', comment], check=False)
        
        # Backup and harden config
        smb_conf_path = '/etc/samba/smb.conf'
        if os.path.exists(smb_conf_path):
            self._run_command(['sudo', 'cp', smb_conf_path, f'{smb_conf_path}.backup'], check=False)
        
        smb_config = """# Samba Configuration - Hardened and Disabled
# Services are masked to prevent accidental startup

[global]
    # Bind to localhost only (if service somehow starts)
    interfaces = lo
    bind interfaces only = yes
    
    # Disable guest access
    map to guest = never
    usershare allow guests = no
    usershare max shares = 0
    
    # Require strong authentication
    client min protocol = SMB3
    server min protocol = SMB3
    client max protocol = SMB3
    server max protocol = SMB3
    
    # Security settings
    server role = standalone server
    security = user
    encrypt passwords = yes
    
    # Disable null sessions
    restrict anonymous = 2
    
    # Disable file/printer sharing
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes
    
    # Logging
    log level = 1
    log file = /var/log/samba/log.%m
    max log size = 1000
    
    # Disable all shares
    browseable = no
"""
        
        self._write_file(smb_conf_path, smb_config)
        
        return {
            'success': True,
            'message': 'SMB secured and disabled',
            'blocked_ports': ['445', '139', '137', '138']
        }
    
    def disable_camera_devices(self) -> dict:
        """
        Disable camera and video capture devices
        - Remove device permissions
        - Blacklist camera kernel modules
        - Block streaming ports
        - Create udev rules to disable webcams
        
        Returns:
            Dict with status and details
        """
        print("[*] Disabling camera devices...")
        
        # Remove video device permissions
        video_devices = list(Path('/dev').glob('video*'))
        for device in video_devices:
            self._run_command(['sudo', 'chmod', '000', str(device)], check=False)
        
        # Blacklist camera modules
        camera_blacklist = """# Blacklist camera and video capture modules for security
blacklist uvcvideo
blacklist videodev
blacklist v4l2_common
blacklist videobuf2_core
blacklist videobuf2_v4l2
blacklist videobuf2_memops
blacklist videobuf2_vmalloc
blacklist usb_video
blacklist gspca_main
blacklist ov534
blacklist sn9c20x
blacklist uvcvideo
"""
        
        self._write_file('/etc/modprobe.d/blacklist-camera.conf', camera_blacklist)
        
        # Udev rules to disable webcams
        udev_rules = """# Disable all webcam and video capture devices
SUBSYSTEM=="video4linux", MODE="0000"
KERNEL=="video[0-9]*", MODE="0000"
SUBSYSTEM=="usb", ATTRS{bInterfaceClass}=="0e", MODE="0000"
"""
        
        self._write_file('/etc/udev/rules.d/99-disable-webcam.rules', udev_rules)
        
        # Block streaming ports
        ports = [
            ('8080/tcp', 'Block webcam-stream'),
            ('8554/tcp', 'Block RTSP'),
            ('1935/tcp', 'Block RTMP'),
            ('5000/tcp', 'Block stream-5000'),
            ('4840/tcp', 'Block Miracast'),
            ('7236/tcp', 'Block Miracast-ctrl')
        ]
        
        for port, comment in ports:
            self._run_command(['sudo', 'ufw', 'deny', port, 'comment', comment], check=False)
        
        return {
            'success': True,
            'message': 'Camera devices disabled',
            'video_devices': [str(d) for d in video_devices],
            'blocked_ports': ['8080', '8554', '1935', '5000', '4840', '7236']
        }
    
    def disable_spying_services(self) -> dict:
        """
        Comprehensive disabling of services that could be used for spying
        - SSH and remote access services
        - Remote desktop and screen sharing
        - Video streaming and casting
        - Network discovery and file sharing
        - Audio capture services
        
        Returns:
            Dict with status and details
        """
        print("[*] Disabling potential spying services...")
        
        # Remote access and SSH-related services
        remote_services = [
            'ssh', 'sshd', 'openssh-server',
            'telnet', 'telnetd',
            'rsh', 'rlogin', 'rexec'
        ]
        
        # Remote desktop services
        remote_desktop_services = [
            'xrdp', 'rdesktop', 'freerdp',
            'vnc4server', 'vncserver', 'tightvncserver', 'x11vnc',
            'tigervnc', 'realvnc-vnc-server',
            'anydesk', 'teamviewer'
        ]
        
        # Screen sharing and casting services
        screen_services = [
            'gnome-remote-desktop',
            'vino', 'screen-share',
            'miraclecast', 'miracast',
            'chromecast-server'
        ]
        
        # File sharing services (potential data exfiltration)
        file_sharing_services = [
            'smbd', 'nmbd', 'samba', 'samba-ad-dc',
            'nfs-server', 'nfs-kernel-server',
            'ftpd', 'vsftpd', 'proftpd', 'pure-ftpd',
            'dropbear'
        ]
        
        # Network discovery services
        discovery_services = [
            'avahi-daemon', 'avahi-dnsconfd',
            'bonjour', 'mdns', 'zeroconf',
            'upnp', 'dlna'
        ]
        
        # Audio capture services
        audio_services = [
            'pulseaudio-server',
            'alsa-state'
        ]
        
        # Web services (potential remote control)
        web_services = [
            'apache2', 'nginx', 'lighttpd', 'httpd',
            'cockpit', 'webmin'
        ]
        
        # Communication / streaming processes (user-level applications)
        communication_processes = {
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
            'rustdesk': 'RustDesk remote access'
        }

        all_services = (remote_services + remote_desktop_services + 
                       screen_services + file_sharing_services + 
                       discovery_services + web_services)
        
        disabled_services = []
        for service in all_services:
            ret1, _, _ = self._run_command(['sudo', 'systemctl', 'disable', '--now', service], check=False)
            ret2, _, _ = self._run_command(['sudo', 'systemctl', 'mask', service], check=False)
            if ret1 == 0 or ret2 == 0:
                disabled_services.append(service)

        terminated_processes = []
        for process_name, label in communication_processes.items():
            ret, _, _ = self._run_command(['pgrep', '-f', process_name], check=False)
            if ret == 0:
                self._run_command(['sudo', 'pkill', '-f', process_name], check=False)
                terminated_processes.append(label)
        
        # Block comprehensive list of spying-related ports
        spy_ports = [
            # SSH and remote access
            ('22/tcp', 'Block SSH'),
            ('23/tcp', 'Block Telnet'),
            ('513/tcp', 'Block rlogin'), 
            ('514/tcp', 'Block rsh'),
            ('512/tcp', 'Block rexec'),
            
            # Remote desktop
            ('3389/tcp', 'Block RDP'),
            ('5900:5910/tcp', 'Block VNC'),
            ('5800:5810/tcp', 'Block VNC-Web'),
            ('6001:6010/tcp', 'Block X11-Forward'),
            
            # Screen sharing and casting
            ('5353/udp', 'Block mDNS/Bonjour'),
            ('1900/udp', 'Block SSDP/UPnP'),
            ('8009/tcp', 'Block Chromecast'),
            ('8008/tcp', 'Block Chromecast-Alt'),
            ('7236/tcp', 'Block Miracast-Ctrl'),
            ('7250/tcp', 'Block Miracast-Data'),
            
            # File sharing
            ('445/tcp', 'Block SMB'),
            ('139/tcp', 'Block NetBIOS'),
            ('137/udp', 'Block NetBIOS-NS'),
            ('138/udp', 'Block NetBIOS-DGM'),
            ('2049/tcp', 'Block NFS'),
            ('111/tcp', 'Block RPC/NFS'),
            ('20/tcp', 'Block FTP-Data'),
            ('21/tcp', 'Block FTP-Control'),
            
            # Streaming protocols
            ('8080/tcp', 'Block HTTP-Alt/Streaming'),
            ('8554/tcp', 'Block RTSP'),
            ('1935/tcp', 'Block RTMP'),
            ('554/tcp', 'Block RTSP-Alt'),
            ('5004/tcp', 'Block RTP'),
            ('5005/tcp', 'Block RTCP'),
            
            # Web-based remote access
            ('80/tcp', 'Block HTTP'),
            ('443/tcp', 'Block HTTPS'),
            ('8443/tcp', 'Block HTTPS-Alt'),
            ('9090/tcp', 'Block Cockpit'),
            ('10000/tcp', 'Block Webmin'),
            
            # Other potential spying ports
            ('5060/tcp', 'Block SIP'),
            ('5061/tcp', 'Block SIP-TLS'),
            ('1723/tcp', 'Block PPTP'),
            ('1701/udp', 'Block L2TP'),
            ('500/udp', 'Block IKE/IPSec'),
            ('4500/udp', 'Block IPSec-NAT')
        ]
        
        blocked_ports = []
        for port, comment in spy_ports:
            ret, _, _ = self._run_command(['sudo', 'ufw', 'deny', port, 'comment', comment], check=False)
            if ret == 0:
                blocked_ports.append(port.split('/')[0])
        
        # Disable audio capture by setting restrictive permissions
        audio_devices = list(Path('/dev/snd').glob('*')) if Path('/dev/snd').exists() else []
        for device in audio_devices:
            self._run_command(['sudo', 'chmod', '600', str(device)], check=False)
        
        # Create additional security configurations
        ssh_disable_config = """# SSH Service Completely Disabled for Security
# This file prevents SSH from starting even if manually enabled
[Unit]
Description=OpenSSH server daemon (DISABLED FOR SECURITY)
After=network.target auditd.service
ConditionPathExists=/etc/ssh/sshd_config

[Service]
Type=notify
ExecStart=/bin/false
ExecReload=/bin/false
KillMode=process
Restart=no

[Install]
WantedBy=multi-user.target
Alias=sshd.service
"""
        
        self._write_file('/etc/systemd/system/ssh.service', ssh_disable_config)
        self._write_file('/etc/systemd/system/sshd.service', ssh_disable_config)
        
        # Reload systemd to apply changes
        self._run_command(['sudo', 'systemctl', 'daemon-reload'], check=False)
        
        return {
            'success': True,
            'message': 'Comprehensive spying services disabled',
            'disabled_services': disabled_services,
            'blocked_ports': blocked_ports,
            'audio_devices_secured': len(audio_devices),
            'terminated_processes': terminated_processes
        }
    
    def disable_unnecessary_servers(self) -> dict:
        """
        Disable unnecessary server services
        - Mask web servers (Apache, Nginx)
        - Mask database servers (MariaDB, PostgreSQL, Redis)
        - Mask network services (SNMP, Avahi, RPC, TFTP)
        - Block all associated ports
        
        Returns:
            Dict with status and details
        """
        print("[*] Disabling unnecessary servers...")
        
        # Services to disable
        services = [
            'apache2',
            'nginx',
            'mariadb',
            'mysql',
            'postgresql',
            'redis-server',
            'snmpd',
            'avahi-daemon',
            'rpcbind',
            'atftpd',
            'tftpd-hpa'
        ]
        
        for service in services:
            self._run_command(['sudo', 'systemctl', 'disable', '--now', service], check=False)
            self._run_command(['sudo', 'systemctl', 'mask', service], check=False)
        
        # Block ports
        ports = [
            ('80/tcp', 'Block HTTP'),
            ('443/tcp', 'Block HTTPS'),
            ('3306/tcp', 'Block MySQL'),
            ('5432/tcp', 'Block PostgreSQL'),
            ('6379/tcp', 'Block Redis'),
            ('161/udp', 'Block SNMP'),
            ('69/udp', 'Block TFTP'),
            ('5353/udp', 'Block mDNS'),
            ('111/tcp', 'Block RPC')
        ]
        
        for port, comment in ports:
            self._run_command(['sudo', 'ufw', 'deny', port, 'comment', comment], check=False)
        
        return {
            'success': True,
            'message': 'Unnecessary servers disabled',
            'masked_services': services,
            'blocked_ports': ['80', '443', '3306', '5432', '6379', '161', '69', '5353', '111']
        }
    
    def remove_passwordless_sudo(self) -> dict:
        """
        Remove passwordless sudo access
        - Modify sudoers configuration to require passwords
        - Backup original configuration
        
        Returns:
            Dict with status and details
        """
        print("[*] Removing passwordless sudo access...")
        
        sudoers_files = [
            '/etc/sudoers.d/kali-grant-root',
            '/etc/sudoers.d/kali-trusted'
        ]
        
        modified_files = []
        
        for sudoers_file in sudoers_files:
            if not os.path.exists(sudoers_file):
                continue
            
            # Backup
            self._run_command(['sudo', 'cp', sudoers_file, f'{sudoers_file}.backup'], check=False)
            
            # Read current content
            ret, content, _ = self._run_command(['sudo', 'cat', sudoers_file])
            if ret != 0:
                continue
            
            # Replace NOPASSWD with password requirement
            if 'NOPASSWD' in content:
                new_content = content.replace('NOPASSWD: ALL', 'ALL')
                new_content = new_content.replace(
                    'without a\n# password prompt',
                    'with password prompt\n# NOPASSWD removed for security - password required for sudo'
                )
                
                self._write_file(sudoers_file, new_content, mode=0o440)
                modified_files.append(sudoers_file)
        
        return {
            'success': True,
            'message': 'Passwordless sudo removed',
            'modified_files': modified_files
        }
    
    def install_security_tools(self) -> dict:
        """
        Install essential security scanning tools
        - rkhunter (rootkit scanner)
        - chkrootkit (rootkit checker)
        - fail2ban (intrusion prevention)
        
        Returns:
            Dict with status and details
        """
        print("[*] Installing security tools...")
        
        tools = ['rkhunter', 'chkrootkit', 'fail2ban']
        
        # Update package list
        self._run_command(['sudo', 'apt-get', 'update', '-qq'], check=False)
        
        # Install tools
        cmd = ['sudo', 'apt-get', 'install', '-y'] + tools
        ret, out, err = self._run_command(cmd, check=False)
        
        return {
            'success': ret == 0,
            'message': 'Security tools installed' if ret == 0 else 'Failed to install some tools',
            'tools': tools
        }

    def disable_inetd_services(self) -> dict:
        """Disable legacy inetd and xinetd super-server daemons."""
        print("[*] Disabling inetd/xinetd super-server services...")

        services = ['inetd', 'xinetd']
        details = []
        overall_success = True
        systemctl_available = shutil.which('systemctl') is not None

        for service in services:
            service_info = {
                'service': service,
                'installed': False,
                'actions': []
            }

            service_paths = [
                f'/usr/sbin/{service}',
                f'/etc/init.d/{service}',
                f'/lib/systemd/system/{service}.service',
                f'/etc/systemd/system/{service}.service'
            ]
            service_installed = any(os.path.exists(path) for path in service_paths)
            service_info['installed'] = service_installed

            if not service_installed:
                service_info['success'] = True
                service_info['actions'].append('Service not present; nothing to harden')
                details.append(service_info)
                continue

            commands = []
            if systemctl_available:
                commands.extend([
                    ['sudo', 'systemctl', 'stop', service],
                    ['sudo', 'systemctl', 'disable', service],
                    ['sudo', 'systemctl', 'mask', service]
                ])
            else:
                commands.extend([
                    ['sudo', 'service', service, 'stop'],
                    ['sudo', 'update-rc.d', service, 'disable']
                ])

            service_success = True
            for cmd in commands:
                ret, _, _ = self._run_command(cmd, check=False)
                cmd_text = ' '.join(cmd)
                if ret != 0 and not self.dry_run:
                    service_success = False
                    overall_success = False
                    service_info['actions'].append(f'FAILED (rc={ret}): {cmd_text}')
                else:
                    prefix = 'Would run' if self.dry_run else 'Executed'
                    service_info['actions'].append(f'{prefix}: {cmd_text}')

            config_file = '/etc/inetd.conf' if service == 'inetd' else '/etc/xinetd.conf'
            if os.path.exists(config_file):
                backup_path = f'{config_file}.flatline-backup'
                ret, _, _ = self._run_command(['sudo', 'cp', config_file, backup_path], check=False)
                if ret != 0 and not self.dry_run:
                    service_success = False
                    overall_success = False
                    service_info['actions'].append(f'FAILED (rc={ret}): backup {config_file}')
                else:
                    action_prefix = 'Would create backup at' if self.dry_run else 'Backup stored at'
                    service_info['actions'].append(f'{action_prefix} {backup_path}')

                hardened_stub = textwrap.dedent(
                    f"""
                    # Flatline Dixie Hardening
                    # {service} disabled. Original configuration stored at {backup_path}
                    # Legacy super-server entries removed to reduce attack surface.
                    #
                    # To restore service functionality, review the backup file and
                    # unmask the associated systemd unit.
                    """
                ).strip() + '\n'

                if self._write_file(config_file, hardened_stub, mode=0o600):
                    action_prefix = 'Would overwrite' if self.dry_run else 'Hardened'
                    service_info['actions'].append(f'{action_prefix} {config_file} with locked-down stub (chmod 600)')
                else:
                    service_success = False
                    overall_success = False
                    service_info['actions'].append(f'FAILED: update {config_file}')
            else:
                service_info['actions'].append(f'Configuration file {config_file} not found')

            if service == 'xinetd':
                dropin_dir = '/etc/xinetd.d'
                if os.path.isdir(dropin_dir):
                    service_info['actions'].append('Review drop-in directory /etc/xinetd.d (service masked so entries stay idle)')

            service_info['success'] = service_success
            details.append(service_info)

        message = 'inetd/xinetd services disabled'
        if not overall_success:
            message = 'inetd/xinetd hardening completed with issues'

        return {
            'success': overall_success,
            'message': message,
            'details': details
        }

    def block_remote_app_traffic(self) -> dict:
        """Block remote access and communication application ports via firewall."""
        print("[*] Blocking remote access and communication application traffic...")
        from .block_remote_apps import apply_remote_app_block

        result = apply_remote_app_block(dry_run=self.dry_run)
        details = {
            'applications': list(result.get('apps', [])),
            'ports': list(result.get('ports', [])),
            'commands': result.get('commands', []),
            'errors': result.get('errors', []),
        }

        return {
            'success': result.get('success', False),
            'message': result.get('message', 'Remote application block completed'),
            'details': details,
        }

    def block_loopback_interfaces(self) -> dict:
        """Block loopback (127.0.0.0/24) connectivity to eliminate local bypass paths."""
        print("[*] Blocking loopback interface traffic...")
        from .loopback_restriction import apply_loopback_block

        result = apply_loopback_block(dry_run=self.dry_run)
        return {
            'success': result.get('success', False),
            'message': result.get('message', 'Loopback restriction applied'),
            'details': {
                'commands': result.get('commands', []),
                'errors': result.get('errors', []),
                'dry_run': result.get('dry_run', False),
            }
        }

    def harden_firewall(self) -> dict:
        """Export firewall configuration and apply hardening policies."""
        print("[*] Exporting firewall configuration and applying hardening...")
        from .firewall_security import apply_firewall_hardening

        result = apply_firewall_hardening(dry_run=self.dry_run)
        message = result.get('message', 'Firewall hardening completed')
        summary = result.get('summary')
        details = {
            'export_file': result.get('export_file'),
            'report_file': result.get('report_file'),
            'hardening_actions': result.get('hardening_actions', []),
        }
        if summary:
            details['summary'] = summary

        return {
            'success': result.get('success', False),
            'message': message,
            'details': details,
        }
    
    def scan_rootkits(self) -> dict:
        """
        Scan system for rootkits
        - Run chkrootkit
        - Run rkhunter
        
        Returns:
            Dict with scan results
        """
        print("[*] Scanning for rootkits...")
        
        results = {}
        
        # Check if tools are installed
        chkrootkit_installed = shutil.which('chkrootkit') is not None
        rkhunter_installed = shutil.which('rkhunter') is not None
        
        if chkrootkit_installed:
            ret, out, err = self._run_command(
                ['sudo', 'chkrootkit', '-q'],
                check=False
            )
            results['chkrootkit'] = {
                'installed': True,
                'clean': 'INFECTED' not in out and 'WARNING' not in out,
                'output': out[:500] if out else 'No issues detected'
            }
        else:
            results['chkrootkit'] = {'installed': False}
        
        if rkhunter_installed:
            ret, out, err = self._run_command(
                ['sudo', 'rkhunter', '--check', '--sk', '--report-warnings-only'],
                check=False
            )
            results['rkhunter'] = {
                'installed': True,
                'output': out[:500] if out else 'No warnings'
            }
        else:
            results['rkhunter'] = {'installed': False}
        
        return {
            'success': True,
            'message': 'Rootkit scan completed',
            'results': results
        }

    def remediate_rootkit_findings(self) -> dict:
        """Remediate warnings raised by rootkit scanners."""
        print("[*] Remediating rootkit scanner warnings...")
        remediation = rootkit_remediation.run_rootkit_remediation(dry_run=self.dry_run)

        if remediation.get('success'):
            print("[+] Rootkit remediation completed successfully.")
        else:
            print("[-] Rootkit remediation encountered issues.")
            for err in remediation.get('errors', []):
                print(f"    {err}")

        return remediation

    def configure_fail2ban(
        self,
        *,
        dry_run_override: Optional[bool] = None,
    ) -> dict:
        """Install, enable, and reload fail2ban using existing configuration."""
        effective_dry_run = self.dry_run if dry_run_override is None else dry_run_override
        print("[*] Configuring fail2ban service...")
        result = fail2ban_hardening.apply_fail2ban_hardening(dry_run=effective_dry_run)
        if result.get('success'):
            print("[+] fail2ban hardened.")
        else:
            print("[-] fail2ban hardening reported issues.")
            for err in (
                result.get('installation', {}).get('stderr'),
                *(result.get('service', {}).get('errors', [])),
                result.get('reload', {}).get('stderr'),
            ):
                if err:
                    print(f"    {err}")
        return result

    def install_firewall_packages(
        self,
        *,
        dry_run_override: Optional[bool] = None,
    ) -> dict:
        """Ensure UFW and iptables tooling is installed and current rules restored."""
        effective_dry_run = self.dry_run if dry_run_override is None else dry_run_override
        print("[*] Installing firewall tooling (ufw/iptables)...")
        result = firewall_installation.install_firewall_packages(dry_run=effective_dry_run)
        if result.get('success'):
            print("[+] Firewall tooling ready.")
        else:
            print("[-] Firewall tooling encountered issues.")
            for step in result.get('steps', []):
                if not step.get('success'):
                    name = step.get('name', 'step')
                    print(f"    {name}: {step.get('message')}")
                    stderr = step.get('stderr')
                    if stderr:
                        print(f"        {stderr}")
                    for err in step.get('errors', []):
                        print(f"        {err}")
        return result

    def cleanup_accounts(
        self,
        *,
        auto_remove: bool = False,
        break_symlinks: bool = False,
        allowed_users: Optional[List[str]] = None,
        allowed_groups: Optional[List[str]] = None,
        base_paths: Optional[List[str]] = None,
        archive_dir: Optional[str] = None,
        use_antivirus: bool = True,
    ) -> dict:
        """Audit and remediate local users, groups, and suspicious symlinks."""
        print("[*] Auditing local accounts and groups...")
        result = account_security.cleanup_accounts(
            auto_remove=auto_remove,
            break_symlinks=break_symlinks,
            dry_run=self.dry_run,
            allowed_users=allowed_users,
            allowed_groups=allowed_groups,
            base_paths=base_paths,
            archive_dir=archive_dir,
            use_antivirus=use_antivirus,
        )
        mode_label = "cleanup" if (auto_remove or break_symlinks) else "audit"
        if result.get('success'):
            print(f"[+] Account {mode_label} completed.")
        else:
            print(f"[-] Account {mode_label} reported issues.")
            for err in result.get('errors', []):
                print(f"    {err}")
        return result
    
    def verify_boot_partitions(self) -> dict:
        """
        Verify boot partitions are clean
        - Check MMC boot partitions
        - Verify they contain no malicious code
        
        Returns:
            Dict with verification results
        """
        print("[*] Verifying boot partitions...")
        
        boot_partitions = ['/dev/mmcblk0boot0', '/dev/mmcblk0boot1']
        results = {}
        
        for partition in boot_partitions:
            if not os.path.exists(partition):
                results[partition] = {'exists': False}
                continue
            
            # Check if read-only
            ro_path = f'/sys/class/block/{os.path.basename(partition)}/ro'
            if os.path.exists(ro_path):
                with open(ro_path, 'r') as f:
                    read_only = f.read().strip() == '1'
            else:
                read_only = False
            
            # Check if empty (all zeros)
            ret, out, err = self._run_command(
                ['sudo', 'cmp', partition, '/dev/zero', '-n', '4194304'],
                check=False
            )
            is_empty = ret == 0
            
            results[partition] = {
                'exists': True,
                'read_only': read_only,
                'empty': is_empty,
                'clean': is_empty and read_only
            }
        
        return {
            'success': True,
            'message': 'Boot partition verification completed',
            'partitions': results
        }
    
    def generate_report(self) -> str:
        """
        Generate comprehensive security hardening report
        
        Returns:
            Report as formatted string
        """
        report = """
=====================================
SYSTEM SECURITY HARDENING REPORT
=====================================

Completed Security Measures:
"""
        
        for result in self.results:
            status = "✓" if result.get('success') else "✗"
            report += f"\n{status} {result.get('message', 'Unknown')}"
        
        report += "\n\n====================================="
        
        return report
    
    def run_full_hardening(self) -> dict:
        """
        Run complete system hardening
        Executes all hardening functions in proper order
        
        Returns:
            Dict with overall results
        """
        print("=" * 60)
        print("STARTING COMPREHENSIVE SYSTEM SECURITY HARDENING")
        print("=" * 60)
        
        # Execute all hardening functions
        self.results.append(self.harden_ssh())
        self.results.append(self.disable_rdp_vnc())
        self.results.append(self.secure_smb())
        self.results.append(self.disable_camera_devices())
        self.results.append(self.disable_spying_services())
        self.results.append(self.disable_unnecessary_servers())
        self.results.append(self.disable_inetd_services())
        self.results.append(self.block_remote_app_traffic())
        self.results.append(self.block_loopback_interfaces())
        self.results.append(self.cleanup_accounts(auto_remove=False, break_symlinks=False))
        self.results.append(self.remove_passwordless_sudo())
        self.results.append(self.install_security_tools())
        self.results.append(self.install_firewall_packages())
        self.results.append(self.configure_fail2ban())
        self.results.append(self.harden_firewall())
        self.results.append(self.scan_rootkits())
        self.results.append(self.remediate_rootkit_findings())
        self.results.append(self.verify_boot_partitions())
        
        # Generate report
        report = self.generate_report()
        print(report)
        
        success_count = sum(1 for r in self.results if r.get('success'))
        total_count = len(self.results)
        
        return {
            'success': success_count == total_count,
            'message': f'Hardening completed: {success_count}/{total_count} successful',
            'report': report,
            'results': self.results
        }


# Convenience functions for individual hardening operations
def harden_ssh(dry_run: bool = False) -> dict:
    """Convenience function to harden SSH"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.harden_ssh()

def disable_rdp_vnc(dry_run: bool = False) -> dict:
    """Convenience function to disable RDP/VNC"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.disable_rdp_vnc()


def secure_smb(dry_run: bool = False) -> dict:
    """Convenience function to secure SMB"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.secure_smb()


def disable_cameras(dry_run: bool = False) -> dict:
    """Convenience function to disable cameras"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.disable_camera_devices()


def disable_servers(dry_run: bool = False) -> dict:
    """Convenience function to disable unnecessary servers"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.disable_unnecessary_servers()


def remove_passwordless_sudo(dry_run: bool = False) -> dict:
    """Convenience function to remove passwordless sudo"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.remove_passwordless_sudo()


def disable_inetd_services(dry_run: bool = False) -> dict:
    """Convenience function to disable inetd/xinetd."""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.disable_inetd_services()


def block_remote_apps(dry_run: bool = False) -> dict:
    """Convenience function to block remote application traffic."""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.block_remote_app_traffic()


def block_loopback(dry_run: bool = False) -> dict:
    """Convenience function to disable loopback connectivity."""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.block_loopback_interfaces()


def configure_fail2ban(dry_run: bool = False) -> dict:
    """Convenience function to configure fail2ban."""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.configure_fail2ban(dry_run_override=dry_run)


def install_firewall_packages(dry_run: bool = False) -> dict:
    """Convenience function to ensure ufw/iptables tooling is installed."""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.install_firewall_packages(dry_run_override=dry_run)


def cleanup_accounts(
    auto_remove: bool = False,
    break_symlinks: bool = False,
    dry_run: bool = False,
    allowed_users: Optional[List[str]] = None,
    allowed_groups: Optional[List[str]] = None,
    base_paths: Optional[List[str]] = None,
    archive_dir: Optional[str] = None,
    use_antivirus: bool = True,
) -> dict:
    """Convenience function to audit and clean accounts and symlinks."""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.cleanup_accounts(
        auto_remove=auto_remove,
        break_symlinks=break_symlinks,
        allowed_users=allowed_users,
        allowed_groups=allowed_groups,
        base_paths=base_paths,
        archive_dir=archive_dir,
        use_antivirus=use_antivirus,
    )


def install_security_tools(dry_run: bool = False) -> dict:
    """Convenience function to install security tools"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.install_security_tools()


def scan_rootkits(dry_run: bool = False) -> dict:
    """Convenience function to scan for rootkits"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.scan_rootkits()


def remediate_rootkit_findings(dry_run: bool = False) -> dict:
    """Convenience function to remediate rootkit scanner warnings."""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.remediate_rootkit_findings()


def verify_boot_partitions(dry_run: bool = False) -> dict:
    """Convenience function to verify boot partitions"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.verify_boot_partitions()


def disable_spying_services(dry_run: bool = False) -> dict:
    """Convenience function to disable spying services"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.disable_spying_services()


def run_integrated_security_suite(dry_run: bool = True) -> Dict[str, Any]:
    """Run the new integrated security suite for enhanced performance"""
    try:
        return integrated_security.run_integrated_security_audit(dry_run=dry_run)
    except Exception as exc:
        return {
            "success": False,
            "message": f"Integrated security suite failed: {exc}",
            "details": {"error": str(exc)}
        }


def run_integrated_hardening_suite(dry_run: bool = True, include_vpn: bool = False) -> Dict[str, Any]:
    """Run the new integrated hardening suite for enhanced performance"""
    try:
        return integrated_security.run_integrated_security_hardening(dry_run=dry_run, include_vpn=include_vpn)
    except Exception as exc:
        return {
            "success": False,
            "message": f"Integrated hardening suite failed: {exc}",
            "details": {"error": str(exc)}
        }


def run_full_hardening(dry_run: bool = True) -> Dict[str, Any]:
    """Convenience function to run full hardening"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.run_full_hardening()


def harden_firewall(dry_run: bool = False) -> dict:
    """Convenience function to harden firewall configuration"""
    hardening = SecurityHardening(dry_run=dry_run)
    return hardening.harden_firewall()