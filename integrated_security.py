#!/usr/bin/env python3
"""
Integrated Security Module
Consolidates all import folder functions into a cohesive, performance-optimized security suite
"""

import os
import sys
import json
import platform
import subprocess
import shlex
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class SecurityResult:
    """Standardized result format for all security operations"""
    module: str
    operation: str
    success: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class IntegratedSecurity:
    """Unified security hardening and auditing system"""
    
    def __init__(self, dry_run: bool = False, parallel: bool = True):
        """
        Initialize integrated security system
        
        Args:
            dry_run: If True, only show what would be done
            parallel: Enable parallel execution where safe
        """
        self.dry_run = dry_run
        self.parallel = parallel
        self.results: List[SecurityResult] = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Performance optimization: cache system info
        self._system_cache = {
            'platform': platform.system(),
            'is_root': os.geteuid() == 0,
            'is_android': self._detect_android(),
            'available_tools': {},
        }
        
        # Remote app blocking configuration (consolidated from import/block_remote_apps.py)
        self.remote_apps = [
            "TeamViewer", "AnyDesk", "Microsoft Remote Desktop (RDP)", "Chrome Remote Desktop",
            "LogMeIn Pro", "Splashtop", "GoToMyPC", "RealVNC", "UltraVNC", 
            "ConnectWise Control (ScreenConnect)", "BeyondTrust Remote Support (Bomgar)",
            "Dameware Remote Support", "RemotePC by IDrive", "Zoho Assist", "NoMachine",
            "Citrix Virtual Apps and Desktops", "VMware Horizon", "Apple Remote Desktop (ARD)",
            "OpenSSH", "RustDesk", "Skype", "WhatsApp", "Telegram", "WeChat", "Line",
            "Discord", "Facebook", "Instagram", "TikTok", "Twitter", "Snapchat", "YouTube",
            "Netflix", "Twitch", "Spotify", "Dropbox", "Google Drive", "OneDrive", "Box",
            "Zoom", "Webex", "Microsoft Teams", "Slack", "Steam", "Epic Games",
            "PlayStation Network", "Xbox Live", "Tor", "Psiphon", "PPTP", "L2TP",
            "IPsec", "OpenVPN", "SSL VPNs", "FTP", "SFTP", "BitTorrent", "eMule",
            "WireGuard", "Shadowsocks", "Jitsi Meet"
        ]
        
        # High-risk ports to block (consolidated from import files)
        self.blocked_ports = [
            22, 80, 443, 3389, 3390, 3391, 5900, 5901, 5902, 5903, 5904, 5905, 5906,
            5907, 5908, 5909, 5800, 5801, 5802, 5803, 5500, 5938, 5939, 6568, 3478,
            5349, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309, 5222, 6783,
            8040, 8041, 6129, 4000, 1494, 2598, 4172, 8443, 3283, 21115, 21116,
            50001, 50002, 6010, 8080, 8081, 4443, 53, 123, 5353, 3479, 3480, 3481,
            1935, 5223, 5228, 5229, 5230, 4244, 5224, 1080, 3128, 8088, 27015,
            27036, 3074, 3659, 25565, 17500, 1194, 1701, 1723, 500, 4500, 9001,
            9030, 9150, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889,
            51413, 5060, 5061, 8801, 8802, 8803, 8804, 8805
        ]
        
        # Media streaming patterns (from secure_media_streams.py)
        self.media_patterns = [
            r"ffmpeg", r"vlc", r"gst-launch", r"gstreamer", r"obs", r"webrtc",
            r"janus", r"mediasoup", r"kurento", r"rtmp", r"rtsp", r"arecord",
            r"parec", r"parecord", r"pw-cat", r"pipewire", r"pulseaudio"
        ]
        
        # Services to disable/mask
        self.target_services = [
            "pipewire.service", "pipewire.socket", "pipewire-pulse.service",
            "pulseaudio.service", "pulseaudio.socket", "rtmp-server.service"
        ]
    
    def _detect_android(self) -> bool:
        """Detect if running on Android"""
        try:
            return ("android" in platform.release().lower() or 
                   "ANDROID_ROOT" in os.environ)
        except Exception:
            return False
    
    def _run_command(self, cmd: str, check: bool = False, capture: bool = True, 
                    timeout: int = 30) -> Tuple[int, str, str]:
        """
        Execute a shell command with performance optimization
        
        Args:
            cmd: Command string to execute
            check: Whether to raise on non-zero exit
            capture: Whether to capture output
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        if self.dry_run:
            print(f"[DRY RUN] Would execute: {cmd}")
            return (0, "", "")
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=capture,
                text=True,
                check=check,
                timeout=timeout
            )
            return (result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return (124, "", f"Command timed out after {timeout}s")
        except subprocess.CalledProcessError as e:
            return (e.returncode, e.stdout or "", e.stderr or "")
        except Exception as e:
            return (1, "", str(e))
    
    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is available (cached for performance)"""
        if tool not in self._system_cache['available_tools']:
            rc, _, _ = self._run_command(f"which {tool}")
            self._system_cache['available_tools'][tool] = rc == 0
        return self._system_cache['available_tools'][tool]
    
    def _get_sudo_prefix(self) -> str:
        """Get appropriate privilege escalation prefix"""
        if self._system_cache['is_root']:
            return ""
        elif self._system_cache['is_android']:
            return "su -c "
        else:
            return "sudo "
    
    # === REMOTE APPLICATION BLOCKING ===
    
    def block_remote_applications(self) -> SecurityResult:
        """Block remote access applications and ports"""
        try:
            if self._system_cache['platform'] == "Windows":
                return self._block_remote_windows()
            else:
                return self._block_remote_linux()
        except Exception as e:
            return SecurityResult(
                module="remote_blocking",
                operation="block_applications",
                success=False,
                message=f"Failed to block remote applications: {e}"
            )
    
    def _block_remote_windows(self) -> SecurityResult:
        """Block remote apps on Windows using firewall rules"""
        port_csv = ",".join(str(p) for p in self.blocked_ports)
        base = 'powershell -NoProfile -NonInteractive -Command '
        
        rules = [
            f'New-NetFirewallRule -DisplayName "FlatlineDixie-Block-In-TCP" -Direction Inbound -Action Block -Protocol TCP -LocalPort {port_csv} -Profile Any -Enabled True -ErrorAction SilentlyContinue',
            f'New-NetFirewallRule -DisplayName "FlatlineDixie-Block-In-UDP" -Direction Inbound -Action Block -Protocol UDP -LocalPort {port_csv} -Profile Any -Enabled True -ErrorAction SilentlyContinue',
            f'New-NetFirewallRule -DisplayName "FlatlineDixie-Block-Out-TCP" -Direction Outbound -Action Block -Protocol TCP -RemotePort {port_csv} -Profile Any -Enabled True -ErrorAction SilentlyContinue',
            f'New-NetFirewallRule -DisplayName "FlatlineDixie-Block-Out-UDP" -Direction Outbound -Action Block -Protocol UDP -RemotePort {port_csv} -Profile Any -Enabled True -ErrorAction SilentlyContinue',
        ]
        
        blocked_count = 0
        for rule in rules:
            rc, stdout, stderr = self._run_command(base + '"' + rule + '"')
            if rc == 0:
                blocked_count += 1
        
        return SecurityResult(
            module="remote_blocking",
            operation="block_applications_windows",
            success=blocked_count > 0,
            message=f"Applied {blocked_count}/4 Windows firewall rules",
            details={"blocked_ports": len(self.blocked_ports), "rules_applied": blocked_count}
        )
    
    def _block_remote_linux(self) -> SecurityResult:
        """Block remote apps on Linux using iptables/ip6tables"""
        sudo = self._get_sudo_prefix()
        blocked_count = 0
        total_rules = 0
        
        for port in self.blocked_ports:
            for proto in ("tcp", "udp"):
                for table in ("iptables", "ip6tables"):
                    if self._check_tool(table):
                        for direction in ("INPUT", "OUTPUT"):
                            port_flag = "--dport" if direction == "INPUT" else "--dport"
                            cmd = f"{sudo}{table} -A {direction} -p {proto} {port_flag} {port} -j REJECT"
                            rc, _, _ = self._run_command(cmd)
                            total_rules += 1
                            if rc == 0:
                                blocked_count += 1
        
        return SecurityResult(
            module="remote_blocking",
            operation="block_applications_linux",
            success=blocked_count > 0,
            message=f"Applied {blocked_count}/{total_rules} iptables rules",
            details={
                "blocked_ports": len(self.blocked_ports),
                "rules_applied": blocked_count,
                "total_attempted": total_rules
            }
        )
    
    # === MEDIA STREAM SECURITY ===
    
    def secure_media_streams(self, terminate_processes: bool = False) -> SecurityResult:
        """Audit and secure media streaming processes and services"""
        try:
            audit_result = self._audit_media_processes()
            service_result = self._secure_media_services()
            
            if terminate_processes:
                terminate_result = self._terminate_media_processes()
                success = all([audit_result['success'], service_result['success'], 
                             terminate_result['success']])
                message = f"Media audit: {audit_result['found']} processes, " \
                         f"Services: {service_result['disabled']}, " \
                         f"Terminated: {terminate_result['terminated']}"
            else:
                success = all([audit_result['success'], service_result['success']])
                message = f"Media audit: {audit_result['found']} processes, " \
                         f"Services: {service_result['disabled']}"
            
            return SecurityResult(
                module="media_security",
                operation="secure_streams",
                success=success,
                message=message,
                details={
                    "audit": audit_result,
                    "services": service_result,
                    "termination": terminate_result if terminate_processes else None
                }
            )
        except Exception as e:
            return SecurityResult(
                module="media_security",
                operation="secure_streams",
                success=False,
                message=f"Failed to secure media streams: {e}"
            )
    
    def _audit_media_processes(self) -> Dict[str, Any]:
        """Audit running media processes"""
        rc, stdout, _ = self._run_command("ps aux")
        if rc != 0:
            return {"success": False, "found": 0, "processes": []}
        
        found_processes = []
        for line in stdout.split('\n'):
            for pattern in self.media_patterns:
                if pattern in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1])
                            if pid not in {1, os.getpid()}:
                                found_processes.append({
                                    "pid": pid,
                                    "pattern": pattern,
                                    "command": " ".join(parts[10:])
                                })
                        except ValueError:
                            continue
        
        return {
            "success": True,
            "found": len(found_processes),
            "processes": found_processes
        }
    
    def _secure_media_services(self) -> Dict[str, Any]:
        """Disable media-related services"""
        if not self._check_tool("systemctl"):
            return {"success": False, "disabled": 0, "services": []}
        
        sudo = self._get_sudo_prefix()
        disabled_services = []
        
        for service in self.target_services:
            # Stop the service
            rc1, _, _ = self._run_command(f"{sudo}systemctl stop {service}")
            # Mask the service
            rc2, _, _ = self._run_command(f"{sudo}systemctl mask {service}")
            
            if rc1 == 0 or rc2 == 0:
                disabled_services.append(service)
        
        return {
            "success": True,
            "disabled": len(disabled_services),
            "services": disabled_services
        }
    
    def _terminate_media_processes(self) -> Dict[str, Any]:
        """Terminate identified media processes"""
        audit = self._audit_media_processes()
        if not audit['success']:
            return {"success": False, "terminated": 0, "processes": []}
        
        terminated = []
        sudo = self._get_sudo_prefix()
        
        for proc in audit['processes']:
            pid = proc['pid']
            rc, _, _ = self._run_command(f"{sudo}kill -TERM {pid}")
            if rc == 0:
                terminated.append(proc)
        
        return {
            "success": True,
            "terminated": len(terminated),
            "processes": terminated
        }
    
    # === REMOTE SERVICES AUDIT ===
    
    def audit_remote_services(self) -> SecurityResult:
        """Comprehensive audit of remote services and connections"""
        try:
            audit_data = {
                "listening_ports": self._get_listening_ports(),
                "enabled_services": self._get_enabled_services(),
                "running_processes": self._get_suspicious_processes(),
                "firewall_status": self._get_firewall_status(),
                "network_connections": self._get_network_connections()
            }
            
            # Generate risk assessment
            risk_score = self._calculate_risk_score(audit_data)
            recommendations = self._generate_recommendations(audit_data)
            
            return SecurityResult(
                module="remote_audit",
                operation="audit_services",
                success=True,
                message=f"Remote services audit completed. Risk score: {risk_score}/100",
                details={
                    "audit_data": audit_data,
                    "risk_score": risk_score,
                    "recommendations": recommendations
                }
            )
        except Exception as e:
            return SecurityResult(
                module="remote_audit",
                operation="audit_services",
                success=False,
                message=f"Failed to audit remote services: {e}"
            )
    
    def _get_listening_ports(self) -> List[Dict[str, Any]]:
        """Get currently listening network ports"""
        rc, stdout, _ = self._run_command("ss -tulpn")
        if rc != 0:
            return []
        
        ports = []
        for line in stdout.split('\n')[1:]:  # Skip header
            if line.strip() and ('LISTEN' in line or 'UNCONN' in line):
                parts = line.split()
                if len(parts) >= 5:
                    ports.append({
                        "protocol": parts[0],
                        "state": parts[1],
                        "local_address": parts[4],
                        "process": parts[6] if len(parts) > 6 else "unknown"
                    })
        return ports
    
    def _get_enabled_services(self) -> List[str]:
        """Get enabled systemd services"""
        if not self._check_tool("systemctl"):
            return []
        
        rc, stdout, _ = self._run_command("systemctl list-unit-files --type=service --state=enabled")
        if rc != 0:
            return []
        
        services = []
        for line in stdout.split('\n'):
            if line.strip() and 'enabled' in line:
                service = line.split()[0]
                services.append(service)
        return services
    
    def _get_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Get processes that might indicate remote access"""
        suspicious_names = ['ssh', 'vnc', 'rdp', 'teamviewer', 'anydesk', 'chrome-remote']
        
        rc, stdout, _ = self._run_command("ps aux")
        if rc != 0:
            return []
        
        processes = []
        for line in stdout.split('\n')[1:]:  # Skip header
            for name in suspicious_names:
                if name in line.lower():
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append({
                            "pid": parts[1],
                            "user": parts[0],
                            "command": " ".join(parts[10:]),
                            "suspicious_keyword": name
                        })
        return processes
    
    def _get_firewall_status(self) -> Dict[str, Any]:
        """Get firewall status and basic rules"""
        status = {"ufw": None, "firewalld": None, "iptables": None}
        
        # Check UFW
        if self._check_tool("ufw"):
            rc, stdout, _ = self._run_command("ufw status")
            status["ufw"] = {"active": "Status: active" in stdout, "rules": stdout}
        
        # Check firewalld
        if self._check_tool("firewall-cmd"):
            rc, stdout, _ = self._run_command("firewall-cmd --state")
            status["firewalld"] = {"active": rc == 0, "state": stdout}
        
        # Check iptables
        if self._check_tool("iptables"):
            rc, stdout, _ = self._run_command("iptables -L -n")
            status["iptables"] = {"available": rc == 0, "rules_count": len(stdout.split('\n'))}
        
        return status
    
    def _get_network_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections"""
        rc, stdout, _ = self._run_command("ss -tuln")
        if rc != 0:
            return []
        
        connections = []
        for line in stdout.split('\n')[1:]:  # Skip header
            if line.strip():
                parts = line.split()
                if len(parts) >= 5:
                    connections.append({
                        "protocol": parts[0],
                        "state": parts[1],
                        "local": parts[4],
                        "remote": parts[5] if len(parts) > 5 else ""
                    })
        return connections
    
    def _calculate_risk_score(self, audit_data: Dict[str, Any]) -> int:
        """Calculate risk score based on audit findings"""
        score = 0
        
        # Listening ports risk
        high_risk_ports = {22, 3389, 5900, 5800, 23}
        for port_info in audit_data["listening_ports"]:
            try:
                port = int(port_info["local_address"].split(":")[-1])
                if port in high_risk_ports:
                    score += 20
                elif port in self.blocked_ports:
                    score += 10
            except (ValueError, IndexError):
                continue
        
        # Suspicious processes risk
        score += len(audit_data["running_processes"]) * 15
        
        # Firewall status risk
        firewall_status = audit_data["firewall_status"]
        if not any(fw and fw.get("active") for fw in firewall_status.values() if fw):
            score += 30
        
        return min(score, 100)  # Cap at 100
    
    def _generate_recommendations(self, audit_data: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on audit"""
        recommendations = []
        
        # Check for high-risk listening ports
        high_risk_ports = {22, 3389, 5900, 5800}
        for port_info in audit_data["listening_ports"]:
            try:
                port = int(port_info["local_address"].split(":")[-1])
                if port in high_risk_ports:
                    recommendations.append(f"Consider restricting access to port {port} ({port_info['protocol']})")
            except (ValueError, IndexError):
                continue
        
        # Check firewall status
        firewall_status = audit_data["firewall_status"]
        if not any(fw and fw.get("active") for fw in firewall_status.values() if fw):
            recommendations.append("Enable and configure a firewall (ufw, firewalld, or iptables)")
        
        # Check for suspicious processes
        if audit_data["running_processes"]:
            recommendations.append("Review and verify necessity of remote access processes")
        
        return recommendations
    
    # === FIREWALL EXPORT AND HARDENING ===
    
    def export_and_harden_firewall(self) -> SecurityResult:
        """Export current firewall configuration and apply hardening"""
        try:
            export_data = self._export_firewall_configs()
            hardening_result = self._apply_firewall_hardening()
            
            # Save export data
            export_path = self._save_firewall_export(export_data)
            
            return SecurityResult(
                module="firewall",
                operation="export_and_harden",
                success=hardening_result["success"],
                message=f"Firewall exported to {export_path}, hardening: {hardening_result['message']}",
                details={
                    "export_path": str(export_path),
                    "export_data": export_data,
                    "hardening": hardening_result
                }
            )
        except Exception as e:
            return SecurityResult(
                module="firewall",
                operation="export_and_harden",
                success=False,
                message=f"Failed to export/harden firewall: {e}"
            )
    
    def _export_firewall_configs(self) -> Dict[str, Any]:
        """Export firewall configurations from all available systems"""
        export_data = {"timestamp": self.session_id}
        
        # Export UFW
        if self._check_tool("ufw"):
            rc, stdout, _ = self._run_command("ufw status verbose")
            export_data["ufw"] = {"status": stdout, "available": True}
        
        # Export firewalld
        if self._check_tool("firewall-cmd"):
            zones_rc, zones_out, _ = self._run_command("firewall-cmd --list-all-zones")
            services_rc, services_out, _ = self._run_command("firewall-cmd --list-services")
            export_data["firewalld"] = {
                "zones": zones_out if zones_rc == 0 else "",
                "services": services_out if services_rc == 0 else "",
                "available": zones_rc == 0
            }
        
        # Export iptables
        if self._check_tool("iptables"):
            ipv4_rc, ipv4_out, _ = self._run_command("iptables -L -n -v")
            ipv6_rc, ipv6_out, _ = self._run_command("ip6tables -L -n -v")
            export_data["iptables"] = {
                "ipv4_rules": ipv4_out if ipv4_rc == 0 else "",
                "ipv6_rules": ipv6_out if ipv6_rc == 0 else "",
                "available": ipv4_rc == 0
            }
        
        return export_data
    
    def _apply_firewall_hardening(self) -> Dict[str, Any]:
        """Apply firewall hardening rules"""
        sudo = self._get_sudo_prefix()
        applied_rules = []
        
        # Basic hardening rules
        hardening_commands = [
            # Drop invalid packets
            f"{sudo}iptables -A INPUT -m conntrack --ctstate INVALID -j DROP",
            # Allow established and related connections
            f"{sudo}iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            # Allow loopback
            f"{sudo}iptables -A INPUT -i lo -j ACCEPT",
            # Rate limit SSH if enabled
            f"{sudo}iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set",
            f"{sudo}iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT",
            # Default policies (if safe to apply)
            f"{sudo}iptables -P FORWARD DROP"
        ]
        
        for cmd in hardening_commands:
            rc, _, _ = self._run_command(cmd)
            if rc == 0:
                applied_rules.append(cmd)
        
        return {
            "success": len(applied_rules) > 0,
            "message": f"Applied {len(applied_rules)}/{len(hardening_commands)} hardening rules",
            "applied_rules": applied_rules
        }
    
    def _save_firewall_export(self, export_data: Dict[str, Any]) -> Path:
        """Save firewall export data to file"""
        export_dir = Path.home() / "flatline_dixie_exports"
        export_dir.mkdir(exist_ok=True)
        
        export_file = export_dir / f"firewall_export_{self.session_id}.json"
        with open(export_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        return export_file
    
    # === VPN SETUP AND MANAGEMENT ===
    
    def setup_vpn_connection(self, config_path: Optional[str] = None, 
                           username: Optional[str] = None, 
                           password: Optional[str] = None) -> SecurityResult:
        """Setup and configure VPN connection"""
        try:
            if not self._check_tool("openvpn"):
                install_result = self._install_vpn_packages()
                if not install_result["success"]:
                    return SecurityResult(
                        module="vpn",
                        operation="setup",
                        success=False,
                        message=f"Failed to install VPN packages: {install_result['message']}"
                    )
            
            config_result = self._configure_vpn(config_path, username, password)
            
            return SecurityResult(
                module="vpn",
                operation="setup",
                success=config_result["success"],
                message=config_result["message"],
                details=config_result
            )
        except Exception as e:
            return SecurityResult(
                module="vpn",
                operation="setup",
                success=False,
                message=f"Failed to setup VPN: {e}"
            )
    
    def _install_vpn_packages(self) -> Dict[str, Any]:
        """Install required VPN packages"""
        sudo = self._get_sudo_prefix()
        packages = ["openvpn", "resolvconf"]
        
        # Update package list
        rc, _, _ = self._run_command(f"{sudo}apt-get update")
        if rc != 0:
            return {"success": False, "message": "Failed to update package list"}
        
        # Install packages
        install_cmd = f"{sudo}apt-get install -y " + " ".join(packages)
        rc, stdout, stderr = self._run_command(install_cmd)
        
        return {
            "success": rc == 0,
            "message": "VPN packages installed successfully" if rc == 0 else f"Installation failed: {stderr}",
            "packages": packages
        }
    
    def _configure_vpn(self, config_path: Optional[str], username: Optional[str], 
                      password: Optional[str]) -> Dict[str, Any]:
        """Configure VPN connection"""
        config_dir = Path("/etc/openvpn/client")
        
        # Find or use provided config
        if config_path and Path(config_path).exists():
            source_config = Path(config_path)
        else:
            # Look for .ovpn files in config directory
            ovpn_files = list(config_dir.glob("*.ovpn"))
            if not ovpn_files:
                return {"success": False, "message": "No OpenVPN config files found"}
            source_config = ovpn_files[0]
        
        # Setup authentication if provided
        auth_configured = False
        if username and password:
            auth_file = config_dir / "auth.txt"
            try:
                sudo = self._get_sudo_prefix()
                auth_content = f"{username}\n{password}\n"
                
                # Write auth file securely
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                    tmp.write(auth_content)
                    tmp_path = tmp.name
                
                rc, _, _ = self._run_command(f"{sudo}mv {tmp_path} {auth_file}")
                if rc == 0:
                    self._run_command(f"{sudo}chmod 600 {auth_file}")
                    auth_configured = True
            except Exception:
                pass
        
        return {
            "success": True,
            "message": f"VPN configured using {source_config.name}",
            "config_file": str(source_config),
            "auth_configured": auth_configured
        }
    
    # === ORCHESTRATION METHODS ===
    
    def run_comprehensive_security_audit(self) -> List[SecurityResult]:
        """Run all security audits and return consolidated results"""
        audit_functions = [
            self.audit_remote_services,
            lambda: self.secure_media_streams(terminate_processes=False),
            self.block_remote_applications,
            self.export_and_harden_firewall
        ]
        
        if self.parallel:
            return self._run_parallel_operations(audit_functions)
        else:
            return [func() for func in audit_functions]
    
    def run_full_security_hardening(self, include_vpn: bool = False) -> List[SecurityResult]:
        """Run complete security hardening suite"""
        hardening_functions = [
            self.block_remote_applications,
            lambda: self.secure_media_streams(terminate_processes=True),
            self.export_and_harden_firewall
        ]
        
        if include_vpn:
            hardening_functions.append(lambda: self.setup_vpn_connection())
        
        if self.parallel:
            return self._run_parallel_operations(hardening_functions)
        else:
            return [func() for func in hardening_functions]
    
    def _run_parallel_operations(self, operations: List[callable]) -> List[SecurityResult]:
        """Execute operations in parallel where safe"""
        results = []
        
        with ThreadPoolExecutor(max_workers=min(len(operations), 4)) as executor:
            future_to_op = {executor.submit(op): op for op in operations}
            
            for future in as_completed(future_to_op):
                try:
                    result = future.result(timeout=300)  # 5 minute timeout
                    results.append(result)
                except Exception as e:
                    results.append(SecurityResult(
                        module="parallel_execution",
                        operation="unknown",
                        success=False,
                        message=f"Operation failed: {e}"
                    ))
        
        return results
    
    def generate_security_report(self, results: List[SecurityResult]) -> str:
        """Generate a comprehensive security report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report_lines = [
            "=" * 80,
            f"FLATLINE DIXIE INTEGRATED SECURITY REPORT",
            f"Generated: {timestamp}",
            f"Session ID: {self.session_id}",
            "=" * 80,
            "",
            "EXECUTIVE SUMMARY:",
            f"- Total operations: {len(results)}",
            f"- Successful: {sum(1 for r in results if r.success)}",
            f"- Failed: {sum(1 for r in results if not r.success)}",
            f"- Dry run mode: {'Yes' if self.dry_run else 'No'}",
            "",
            "DETAILED RESULTS:",
            ""
        ]
        
        for i, result in enumerate(results, 1):
            status = "✓ SUCCESS" if result.success else "✗ FAILED"
            report_lines.extend([
                f"{i}. {result.module.upper()} - {result.operation}",
                f"   Status: {status}",
                f"   Message: {result.message}",
                f"   Timestamp: {result.timestamp}",
                ""
            ])
            
            if result.details:
                report_lines.append("   Details:")
                for key, value in result.details.items():
                    if isinstance(value, (dict, list)):
                        report_lines.append(f"     {key}: {len(value) if isinstance(value, list) else 'object'}")
                    else:
                        report_lines.append(f"     {key}: {value}")
                report_lines.append("")
        
        # Add recommendations
        failed_operations = [r for r in results if not r.success]
        if failed_operations:
            report_lines.extend([
                "RECOMMENDATIONS:",
                ""
            ])
            for result in failed_operations:
                report_lines.append(f"- Review and retry: {result.module} - {result.operation}")
            report_lines.append("")
        
        report_lines.extend([
            "=" * 80,
            "End of Report",
            "=" * 80
        ])
        
        return "\n".join(report_lines)


# === CONVENIENCE FUNCTIONS FOR GUI INTEGRATION ===

def run_integrated_security_audit(dry_run: bool = False) -> Dict[str, Any]:
    """Convenience function for GUI integration - security audit"""
    security = IntegratedSecurity(dry_run=dry_run, parallel=True)
    results = security.run_comprehensive_security_audit()
    report = security.generate_security_report(results)
    
    return {
        "success": all(r.success for r in results),
        "message": f"Security audit completed. {sum(1 for r in results if r.success)}/{len(results)} operations successful.",
        "report": report,
        "results": results
    }

def run_integrated_security_hardening(dry_run: bool = False, include_vpn: bool = False) -> Dict[str, Any]:
    """Convenience function for GUI integration - security hardening"""
    security = IntegratedSecurity(dry_run=dry_run, parallel=True)
    results = security.run_full_security_hardening(include_vpn=include_vpn)
    report = security.generate_security_report(results)
    
    return {
        "success": all(r.success for r in results),
        "message": f"Security hardening completed. {sum(1 for r in results if r.success)}/{len(results)} operations successful.",
        "report": report,
        "results": results
    }

def get_integrated_security_summary() -> str:
    """Get a summary of integrated security capabilities"""
    return """Integrated Security Module Status:
- Remote Application Blocking: Available
- Media Stream Security: Available  
- Remote Services Audit: Available
- Firewall Export/Hardening: Available
- VPN Setup/Management: Available
- Parallel Processing: Enabled
- Cross-Platform Support: Windows/Linux/Android

Modules consolidated: block_remote_apps, openvpn_setup, remote_services_audit, 
secure_media_streams, firewall_security_exporter, system_security_hardening

Performance optimizations: Command caching, parallel execution, timeout handling"""


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Flatline Dixie Integrated Security Suite")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    parser.add_argument("--operation", choices=["audit", "harden", "block-remote", "secure-media", "setup-vpn"], 
                       default="audit", help="Operation to perform")
    parser.add_argument("--include-vpn", action="store_true", help="Include VPN setup in hardening")
    parser.add_argument("--terminate-media", action="store_true", help="Terminate media processes")
    
    args = parser.parse_args()
    
    security = IntegratedSecurity(dry_run=args.dry_run, parallel=True)
    
    if args.operation == "audit":
        results = security.run_comprehensive_security_audit()
    elif args.operation == "harden":
        results = security.run_full_security_hardening(include_vpn=args.include_vpn)
    elif args.operation == "block-remote":
        results = [security.block_remote_applications()]
    elif args.operation == "secure-media":
        results = [security.secure_media_streams(terminate_processes=args.terminate_media)]
    elif args.operation == "setup-vpn":
        results = [security.setup_vpn_connection()]
    
    report = security.generate_security_report(results)
    print(report)
    
    # Save report to file
    report_file = Path.home() / f"flatline_dixie_report_{security.session_id}.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"\nReport saved to: {report_file}")