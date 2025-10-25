#!/usr/bin/env python3
"""
System Security Hardening Script
Modular functions for comprehensive Linux system security hardening
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Tuple, List, Optional


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
"""
        
        self._write_file('/etc/modprobe.d/blacklist-camera.conf', camera_blacklist)
        
        # Udev rules to disable webcams
        udev_rules = """# Disable all webcam and video capture devices
SUBSYSTEM=="video4linux", MODE="0000"
KERNEL=="video[0-9]*", MODE="0000"
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
        self.results.append(self.disable_unnecessary_servers())
        self.results.append(self.remove_passwordless_sudo())
        self.results.append(self.install_security_tools())
        self.results.append(self.scan_rootkits())
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


def main():
    """Main function to run security hardening"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='System Security Hardening Script'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without executing'
    )
    parser.add_argument(
        '--function',
        choices=[
            'ssh', 'rdp', 'smb', 'camera', 'servers',
            'sudo', 'tools', 'scan', 'boot', 'all'
        ],
        default='all',
        help='Specific function to run (default: all)'
    )
    
    args = parser.parse_args()
    
    # Check if running as root or with sudo
    if os.geteuid() != 0 and not args.dry_run:
        print("Warning: This script requires root/sudo privileges")
        print("Rerun with: sudo python3 system_security_hardening.py")
        return 1
    
    hardening = SecurityHardening(dry_run=args.dry_run)
    
    # Run specific function or all
    if args.function == 'all':
        result = hardening.run_full_hardening()
    else:
        function_map = {
            'ssh': hardening.harden_ssh,
            'rdp': hardening.disable_rdp_vnc,
            'smb': hardening.secure_smb,
            'camera': hardening.disable_camera_devices,
            'servers': hardening.disable_unnecessary_servers,
            'sudo': hardening.remove_passwordless_sudo,
            'tools': hardening.install_security_tools,
            'scan': hardening.scan_rootkits,
            'boot': hardening.verify_boot_partitions
        }
        result = function_map[args.function]()
        print(f"\n{result['message']}")
    
    return 0 if result['success'] else 1


if __name__ == '__main__':
    exit(main())
