#!/usr/bin/env python3
"""
Remote Services Audit Script
Creates a comprehensive list of all remote services ever and currently in use
"""

import subprocess
import json
import re
from datetime import datetime
from pathlib import Path


class RemoteServicesAuditor:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.audit_data = {
            "timestamp": self.timestamp,
            "currently_listening": [],
            "installed_packages": [],
            "enabled_services": [],
            "masked_services": [],
            "running_processes": [],
            "historical_connections": [],
            "firewall_rules": {},
            "recommendations": []
        }
    
    def run_command(self, cmd):
        """Run shell command and return output"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip(), result.returncode
        except Exception as e:
            return str(e), 1
    
    def get_listening_ports(self):
        """Get currently listening network ports"""
        print("[*] Scanning for listening network ports...")
        
        output, rc = self.run_command("ss -tulpn")
        if rc == 0:
            lines = output.split('\n')
            for line in lines:
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        local_addr = parts[4]
                        process = parts[-1] if len(parts) > 6 else "unknown"
                        
                        # Parse port from address
                        port = local_addr.split(':')[-1]
                        
                        service_info = {
                            "protocol": proto,
                            "local_address": local_addr,
                            "port": port,
                            "process": process,
                            "service_type": self.identify_service_type(port)
                        }
                        self.audit_data["currently_listening"].append(service_info)
        
        print(f"  [+] Found {len(self.audit_data['currently_listening'])} listening services")
    
    def identify_service_type(self, port):
        """Identify service type based on port number"""
        common_ports = {
            "20": "FTP Data",
            "21": "FTP Control",
            "22": "SSH",
            "23": "Telnet",
            "25": "SMTP",
            "53": "DNS",
            "69": "TFTP",
            "80": "HTTP",
            "110": "POP3",
            "135": "MS RPC",
            "137": "NetBIOS Name",
            "138": "NetBIOS Datagram",
            "139": "NetBIOS Session",
            "143": "IMAP",
            "389": "LDAP",
            "443": "HTTPS",
            "445": "SMB",
            "465": "SMTPS",
            "513": "rlogin",
            "514": "rsh",
            "587": "SMTP Submission",
            "631": "IPP/CUPS",
            "873": "rsync",
            "989": "FTPS Data",
            "990": "FTPS Control",
            "993": "IMAPS",
            "995": "POP3S",
            "1433": "MS SQL",
            "1521": "Oracle DB",
            "1723": "PPTP",
            "3306": "MySQL",
            "3389": "RDP",
            "5355": "LLMNR",
            "5432": "PostgreSQL",
            "5800": "VNC HTTP",
            "5900": "VNC",
            "5901": "VNC Display 1",
            "5902": "VNC Display 2",
            "6881": "BitTorrent",
            "8080": "HTTP Alternate",
            "8443": "HTTPS Alternate",
            "9090": "WebSM/Cockpit",
            "27017": "MongoDB",
        }
        return common_ports.get(str(port), "Unknown")
    
    def get_installed_remote_packages(self):
        """Get installed packages related to remote access"""
        print("[*] Scanning for installed remote access packages...")
        
        remote_keywords = [
            'ssh', 'openssh', 'vnc', 'rdp', 'xrdp', 'rdesktop', 'freerdp',
            'telnet', 'ftp', 'tftp', 'rsh', 'rlogin', 'remote', 'anydesk',
            'teamviewer', 'nomachine', 'x2go', 'spice', 'guacamole',
            'cockpit', 'webmin', 'rsync', 'sftp', 'scp'
        ]
        
        for keyword in remote_keywords:
            output, rc = self.run_command(f"dpkg -l | grep -i {keyword}")
            if rc == 0 and output:
                for line in output.split('\n'):
                    if line.startswith('ii'):
                        parts = line.split()
                        if len(parts) >= 3:
                            pkg_info = {
                                "package": parts[1],
                                "version": parts[2],
                                "keyword": keyword,
                                "description": ' '.join(parts[3:]) if len(parts) > 3 else ""
                            }
                            if pkg_info not in self.audit_data["installed_packages"]:
                                self.audit_data["installed_packages"].append(pkg_info)
        
        print(f"  [+] Found {len(self.audit_data['installed_packages'])} installed packages")
    
    def get_service_status(self):
        """Get status of remote services"""
        print("[*] Checking service status...")
        
        services_to_check = [
            'ssh', 'sshd', 'openssh-server',
            'vnc', 'vncserver', 'tightvncserver', 'x11vnc',
            'xrdp', 'rdp',
            'gnome-remote-desktop',
            'telnet', 'telnetd',
            'ftpd', 'vsftpd', 'proftpd',
            'rsh', 'rlogin',
            'cockpit', 'cockpit.socket',
            'anydesk', 'teamviewer',
            'x2goserver',
            'nomachine',
            'rsync', 'rsyncd'
        ]
        
        for service in services_to_check:
            output, rc = self.run_command(f"systemctl status {service} 2>&1")
            
            if 'could not be found' not in output.lower():
                status_info = {
                    "service": service,
                    "status": "unknown",
                    "loaded": "unknown",
                    "active": "unknown"
                }
                
                # Parse output
                for line in output.split('\n'):
                    if 'Loaded:' in line:
                        if 'masked' in line.lower():
                            status_info["loaded"] = "masked"
                        elif 'not-found' in line.lower():
                            status_info["loaded"] = "not-found"
                        elif 'loaded' in line.lower():
                            status_info["loaded"] = "loaded"
                    
                    if 'Active:' in line:
                        if 'active (running)' in line.lower():
                            status_info["active"] = "running"
                        elif 'inactive' in line.lower():
                            status_info["active"] = "inactive"
                        elif 'failed' in line.lower():
                            status_info["active"] = "failed"
                
                if status_info["loaded"] == "masked":
                    self.audit_data["masked_services"].append(status_info)
                elif status_info["active"] == "running":
                    self.audit_data["enabled_services"].append(status_info)
                elif status_info["loaded"] == "loaded":
                    self.audit_data["enabled_services"].append(status_info)
        
        print(f"  [+] Found {len(self.audit_data['enabled_services'])} enabled services")
        print(f"  [+] Found {len(self.audit_data['masked_services'])} masked services")
    
    def get_running_processes(self):
        """Get running processes related to remote access"""
        print("[*] Scanning for running remote access processes...")
        
        output, rc = self.run_command("ps aux")
        if rc == 0:
            remote_keywords = [
                'sshd', 'ssh', 'vnc', 'rdp', 'xrdp', 'telnet', 'ftp',
                'rsh', 'rlogin', 'remote', 'anydesk', 'teamviewer'
            ]
            
            for line in output.split('\n'):
                for keyword in remote_keywords:
                    if keyword in line.lower() and 'grep' not in line:
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            process_info = {
                                "user": parts[0],
                                "pid": parts[1],
                                "cpu": parts[2],
                                "mem": parts[3],
                                "command": parts[10]
                            }
                            if process_info not in self.audit_data["running_processes"]:
                                self.audit_data["running_processes"].append(process_info)
                        break
        
        print(f"  [+] Found {len(self.audit_data['running_processes'])} running processes")
    
    def check_auth_logs(self):
        """Check authentication logs for remote access history"""
        print("[*] Checking authentication logs for remote access history...")
        
        log_files = [
            '/var/log/auth.log',
            '/var/log/auth.log.1',
            '/var/log/secure',
            '/var/log/secure.1'
        ]
        
        for log_file in log_files:
            output, rc = self.run_command(f"cat {log_file} 2>&1 | grep -E 'sshd|vnc|rdp|Accepted|Failed password' | tail -100")
            if rc == 0 and output and 'cannot open' not in output.lower():
                for line in output.split('\n'):
                    if line.strip():
                        self.audit_data["historical_connections"].append(line)
        
        print(f"  [+] Found {len(self.audit_data['historical_connections'])} historical connection entries")
    
    def check_firewall_rules(self):
        """Check firewall rules for remote services"""
        print("[*] Checking firewall rules...")
        
        # Check UFW
        output, rc = self.run_command("sudo ufw status numbered 2>&1")
        if rc == 0 and 'inactive' not in output.lower():
            self.audit_data["firewall_rules"]["ufw"] = output
        
        # Check firewalld
        output, rc = self.run_command("sudo firewall-cmd --list-all 2>&1")
        if rc == 0:
            self.audit_data["firewall_rules"]["firewalld"] = output
        
        # Check iptables
        output, rc = self.run_command("sudo iptables -L -n 2>&1")
        if rc == 0:
            self.audit_data["firewall_rules"]["iptables"] = output
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        print("[*] Generating security recommendations...")
        
        recommendations = []
        
        # Check for unencrypted protocols
        risky_services = ['telnet', 'ftp', 'rsh', 'rlogin', 'tftp']
        for pkg in self.audit_data["installed_packages"]:
            for risky in risky_services:
                if risky in pkg["package"].lower():
                    recommendations.append({
                        "severity": "HIGH",
                        "issue": f"Insecure protocol installed: {pkg['package']}",
                        "recommendation": f"Remove {risky.upper()} and use secure alternatives (SSH, SFTP, SCP)"
                    })
        
        # Check for running SSH
        ssh_running = any('ssh' in str(svc).lower() for svc in self.audit_data["enabled_services"])
        if ssh_running:
            recommendations.append({
                "severity": "MEDIUM",
                "issue": "SSH service is enabled",
                "recommendation": "Ensure SSH is hardened: disable root login, use key authentication, change default port"
            })
        
        # Check for VNC
        vnc_installed = any('vnc' in pkg["package"].lower() for pkg in self.audit_data["installed_packages"])
        if vnc_installed:
            recommendations.append({
                "severity": "MEDIUM",
                "issue": "VNC is installed",
                "recommendation": "Use SSH tunneling for VNC or switch to more secure alternatives like RDP with TLS"
            })
        
        # Check for open ports
        if self.audit_data["currently_listening"]:
            recommendations.append({
                "severity": "INFO",
                "issue": f"{len(self.audit_data['currently_listening'])} network services are listening",
                "recommendation": "Review all listening services and close unnecessary ports"
            })
        
        # Check firewall status
        if not self.audit_data["firewall_rules"]:
            recommendations.append({
                "severity": "CRITICAL",
                "issue": "No firewall configuration detected",
                "recommendation": "Enable and configure firewall (UFW or firewalld)"
            })
        
        self.audit_data["recommendations"] = recommendations
        print(f"  [+] Generated {len(recommendations)} recommendations")
    
    def save_json_report(self):
        """Save detailed JSON report"""
        output_file = f"/home/pencil1/Documents/remote_services_audit_{self.timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.audit_data, f, indent=2)
        
        print(f"\n[+] JSON report saved to: {output_file}")
        return output_file
    
    def save_text_report(self):
        """Save human-readable text report"""
        report_file = f"/home/pencil1/Documents/remote_services_report_{self.timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("REMOTE SERVICES AUDIT REPORT\n")
            f.write(f"Generated: {self.timestamp}\n")
            f.write("=" * 80 + "\n\n")
            
            # Currently Listening Services
            f.write("CURRENTLY LISTENING NETWORK SERVICES\n")
            f.write("-" * 80 + "\n")
            if self.audit_data["currently_listening"]:
                for svc in self.audit_data["currently_listening"]:
                    f.write(f"  • {svc['protocol']} Port {svc['port']} - {svc['service_type']}\n")
                    f.write(f"    Address: {svc['local_address']}\n")
                    f.write(f"    Process: {svc['process']}\n\n")
            else:
                f.write("  No listening services detected\n\n")
            
            # Installed Packages
            f.write("\nINSTALLED REMOTE ACCESS PACKAGES\n")
            f.write("-" * 80 + "\n")
            if self.audit_data["installed_packages"]:
                categories = {}
                for pkg in self.audit_data["installed_packages"]:
                    keyword = pkg["keyword"]
                    if keyword not in categories:
                        categories[keyword] = []
                    categories[keyword].append(pkg)
                
                for keyword, pkgs in sorted(categories.items()):
                    f.write(f"\n{keyword.upper()} Related:\n")
                    for pkg in pkgs:
                        f.write(f"  • {pkg['package']} ({pkg['version']})\n")
            else:
                f.write("  No remote access packages found\n")
            
            # Service Status
            f.write("\n\nENABLED/LOADED SERVICES\n")
            f.write("-" * 80 + "\n")
            if self.audit_data["enabled_services"]:
                for svc in self.audit_data["enabled_services"]:
                    f.write(f"  • {svc['service']}: {svc['active']} ({svc['loaded']})\n")
            else:
                f.write("  No enabled remote services\n")
            
            # Masked Services
            f.write("\n\nMASKED/DISABLED SERVICES (Previously Installed)\n")
            f.write("-" * 80 + "\n")
            if self.audit_data["masked_services"]:
                for svc in self.audit_data["masked_services"]:
                    f.write(f"  • {svc['service']}: {svc['loaded']}\n")
            else:
                f.write("  No masked services\n")
            
            # Running Processes
            f.write("\n\nRUNNING REMOTE ACCESS PROCESSES\n")
            f.write("-" * 80 + "\n")
            if self.audit_data["running_processes"]:
                for proc in self.audit_data["running_processes"]:
                    f.write(f"  • PID {proc['pid']} ({proc['user']}): {proc['command'][:60]}\n")
            else:
                f.write("  No remote access processes running\n")
            
            # Historical Connections
            f.write("\n\nHISTORICAL REMOTE ACCESS ATTEMPTS (Recent)\n")
            f.write("-" * 80 + "\n")
            if self.audit_data["historical_connections"]:
                for entry in self.audit_data["historical_connections"][-50:]:  # Last 50
                    f.write(f"  {entry}\n")
            else:
                f.write("  No historical data available\n")
            
            # Firewall Rules
            f.write("\n\nFIREWALL CONFIGURATION\n")
            f.write("-" * 80 + "\n")
            if self.audit_data["firewall_rules"]:
                for fw_type, rules in self.audit_data["firewall_rules"].items():
                    f.write(f"\n{fw_type.upper()}:\n")
                    f.write(rules[:500] + "\n")  # Truncate if too long
            else:
                f.write("  No firewall configuration detected\n")
            
            # Recommendations
            f.write("\n\nSECURITY RECOMMENDATIONS\n")
            f.write("=" * 80 + "\n")
            if self.audit_data["recommendations"]:
                for rec in self.audit_data["recommendations"]:
                    f.write(f"\n[{rec['severity']}] {rec['issue']}\n")
                    f.write(f"  → {rec['recommendation']}\n")
            else:
                f.write("  No specific recommendations\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        print(f"[+] Text report saved to: {report_file}")
        return report_file
    
    def run_audit(self):
        """Run complete audit"""
        print("=" * 80)
        print("REMOTE SERVICES AUDIT")
        print("=" * 80)
        print()
        
        self.get_listening_ports()
        self.get_installed_remote_packages()
        self.get_service_status()
        self.get_running_processes()
        self.check_auth_logs()
        self.check_firewall_rules()
        self.generate_recommendations()
        
        print("\n" + "=" * 80)
        json_file = self.save_json_report()
        text_file = self.save_text_report()
        
        print("\n[+] Audit complete!")
        print("=" * 80)
        
        return json_file, text_file


def main():
    auditor = RemoteServicesAuditor()
    auditor.run_audit()


if __name__ == "__main__":
    main()
