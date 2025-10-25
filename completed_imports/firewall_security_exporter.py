#!/usr/bin/env python3
"""
Firewall Security Exporter and Hardening Script
Exports firewalld and UFW configurations and applies security hardening
"""

import subprocess
import json
import sys
from datetime import datetime
from pathlib import Path


class FirewallExporter:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.export_data = {
            "timestamp": self.timestamp,
            "firewalld": {},
            "ufw": {},
            "security_applied": []
        }
    
    def run_command(self, cmd, check=False):
        """Run a shell command and return output"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=check
            )
            return result.stdout.strip(), result.returncode
        except subprocess.CalledProcessError as e:
            return e.stdout.strip(), e.returncode
    
    def check_tool_exists(self, tool):
        """Check if a tool is installed"""
        output, rc = self.run_command(f"which {tool}")
        return rc == 0
    
    def export_firewalld(self):
        """Export firewalld configuration"""
        print("[*] Exporting firewalld configuration...")
        
        if not self.check_tool_exists("firewall-cmd"):
            print("[-] firewall-cmd not found")
            return
        
        # Check if firewalld is running
        output, rc = self.run_command("systemctl is-active firewalld")
        self.export_data["firewalld"]["active"] = (output == "active")
        
        # Get default zone
        output, rc = self.run_command("sudo firewall-cmd --get-default-zone")
        if rc == 0:
            self.export_data["firewalld"]["default_zone"] = output
        
        # Get active zones
        output, rc = self.run_command("sudo firewall-cmd --get-active-zones")
        if rc == 0:
            self.export_data["firewalld"]["active_zones"] = output
        
        # Get all zones configuration
        output, rc = self.run_command("sudo firewall-cmd --list-all-zones")
        if rc == 0:
            self.export_data["firewalld"]["all_zones"] = output
        
        # Get available services
        output, rc = self.run_command("sudo firewall-cmd --get-services")
        if rc == 0:
            self.export_data["firewalld"]["available_services"] = output.split()
        
        # Get enabled services in default zone
        output, rc = self.run_command("sudo firewall-cmd --list-services")
        if rc == 0:
            self.export_data["firewalld"]["enabled_services"] = output.split()
        
        # Get ports
        output, rc = self.run_command("sudo firewall-cmd --list-ports")
        if rc == 0:
            self.export_data["firewalld"]["open_ports"] = output.split()
        
        print(f"[+] Firewalld configuration exported")
    
    def export_ufw(self):
        """Export UFW configuration"""
        print("[*] Exporting UFW configuration...")
        
        if not self.check_tool_exists("ufw"):
            print("[-] ufw not found")
            return
        
        # Get UFW status
        output, rc = self.run_command("sudo ufw status verbose")
        if rc == 0:
            self.export_data["ufw"]["status"] = output
        
        # Get UFW numbered rules
        output, rc = self.run_command("sudo ufw status numbered")
        if rc == 0:
            self.export_data["ufw"]["rules_numbered"] = output
        
        # Check if UFW is enabled
        output, rc = self.run_command("systemctl is-active ufw")
        self.export_data["ufw"]["active"] = (output == "active")
        
        # Get UFW application list
        output, rc = self.run_command("sudo ufw app list")
        if rc == 0:
            self.export_data["ufw"]["available_apps"] = output
        
        print(f"[+] UFW configuration exported")
    
    def apply_firewalld_hardening(self):
        """Apply security hardening to firewalld"""
        print("\n[*] Applying firewalld security hardening...")
        
        if not self.check_tool_exists("firewall-cmd"):
            return
        
        hardening_rules = []
        
        # Ensure firewalld is enabled and running
        output, rc = self.run_command("sudo systemctl enable firewalld")
        if rc == 0:
            hardening_rules.append("Enabled firewalld service")
        
        output, rc = self.run_command("sudo systemctl start firewalld")
        if rc == 0:
            hardening_rules.append("Started firewalld service")
        
        # Set default zone to drop (most restrictive) or public
        output, rc = self.run_command("sudo firewall-cmd --set-default-zone=public")
        if rc == 0:
            hardening_rules.append("Set default zone to public")
        
        # Block common attack services
        risky_services = [
            "telnet", "ftp", "tftp", "rsh", "rlogin", "finger",
            "netbios-ns", "netbios-dgm", "netbios-ssn", "microsoft-ds"
        ]
        
        for service in risky_services:
            output, rc = self.run_command(f"sudo firewall-cmd --permanent --remove-service={service}")
            if rc == 0:
                hardening_rules.append(f"Blocked risky service: {service}")
        
        # Enable panic mode protection (can be used in emergency)
        # Note: Don't actually enable it now, just document
        hardening_rules.append("Panic mode available: firewall-cmd --panic-on")
        
        # Reload firewall to apply changes
        output, rc = self.run_command("sudo firewall-cmd --reload")
        if rc == 0:
            hardening_rules.append("Reloaded firewalld configuration")
        
        self.export_data["security_applied"].extend(hardening_rules)
        
        for rule in hardening_rules:
            print(f"  [+] {rule}")
    
    def apply_ufw_hardening(self):
        """Apply security hardening to UFW"""
        print("\n[*] Applying UFW security hardening...")
        
        if not self.check_tool_exists("ufw"):
            return
        
        hardening_rules = []
        
        # Set default policies (deny incoming, allow outgoing)
        output, rc = self.run_command("sudo ufw default deny incoming")
        if rc == 0:
            hardening_rules.append("Set default deny for incoming traffic")
        
        output, rc = self.run_command("sudo ufw default allow outgoing")
        if rc == 0:
            hardening_rules.append("Set default allow for outgoing traffic")
        
        output, rc = self.run_command("sudo ufw default deny routed")
        if rc == 0:
            hardening_rules.append("Set default deny for routed traffic")
        
        # Enable logging
        output, rc = self.run_command("sudo ufw logging on")
        if rc == 0:
            hardening_rules.append("Enabled UFW logging")
        
        # Deny known risky ports
        risky_ports = [
            (23, "tcp", "Telnet"),
            (21, "tcp", "FTP"),
            (69, "udp", "TFTP"),
            (135, "tcp", "MS RPC"),
            (137, "udp", "NetBIOS NS"),
            (138, "udp", "NetBIOS DGM"),
            (139, "tcp", "NetBIOS SSN"),
            (445, "tcp", "SMB"),
        ]
        
        for port, proto, desc in risky_ports:
            output, rc = self.run_command(f"sudo ufw deny {port}/{proto} comment '{desc}'")
            if rc == 0:
                hardening_rules.append(f"Denied risky port {port}/{proto} ({desc})")
        
        # Enable rate limiting on SSH if it exists
        output, rc = self.run_command("sudo ufw limit 22/tcp comment 'SSH rate limit'")
        if rc == 0:
            hardening_rules.append("Applied rate limiting to SSH (port 22)")
        
        # Enable UFW
        output, rc = self.run_command("yes | sudo ufw enable")
        if rc == 0:
            hardening_rules.append("Enabled UFW firewall")
        
        self.export_data["security_applied"].extend(hardening_rules)
        
        for rule in hardening_rules:
            print(f"  [+] {rule}")
    
    def save_export(self):
        """Save exported data to file"""
        output_file = f"/home/pencil1/Documents/firewall_export_{self.timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.export_data, f, indent=2)
        
        print(f"\n[+] Export saved to: {output_file}")
        return output_file
    
    def generate_report(self):
        """Generate a human-readable report"""
        report_file = f"/home/pencil1/Documents/firewall_security_report_{self.timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("FIREWALL SECURITY EXPORT AND HARDENING REPORT\n")
            f.write(f"Generated: {self.timestamp}\n")
            f.write("=" * 80 + "\n\n")
            
            # Firewalld section
            f.write("FIREWALLD CONFIGURATION\n")
            f.write("-" * 80 + "\n")
            if self.export_data["firewalld"]:
                f.write(f"Status: {'Active' if self.export_data['firewalld'].get('active') else 'Inactive'}\n")
                f.write(f"Default Zone: {self.export_data['firewalld'].get('default_zone', 'N/A')}\n")
                f.write(f"Enabled Services: {', '.join(self.export_data['firewalld'].get('enabled_services', []))}\n")
                f.write(f"Open Ports: {', '.join(self.export_data['firewalld'].get('open_ports', []))}\n\n")
                
                if 'all_zones' in self.export_data['firewalld']:
                    f.write("All Zones Configuration:\n")
                    f.write(self.export_data['firewalld']['all_zones'] + "\n\n")
            else:
                f.write("Firewalld not configured or not found\n\n")
            
            # UFW section
            f.write("UFW CONFIGURATION\n")
            f.write("-" * 80 + "\n")
            if self.export_data["ufw"]:
                f.write(f"Status: {'Active' if self.export_data['ufw'].get('active') else 'Inactive'}\n\n")
                
                if 'status' in self.export_data['ufw']:
                    f.write("UFW Status:\n")
                    f.write(self.export_data['ufw']['status'] + "\n\n")
                
                if 'rules_numbered' in self.export_data['ufw']:
                    f.write("UFW Rules:\n")
                    f.write(self.export_data['ufw']['rules_numbered'] + "\n\n")
            else:
                f.write("UFW not configured or not found\n\n")
            
            # Security hardening applied
            f.write("SECURITY HARDENING APPLIED\n")
            f.write("-" * 80 + "\n")
            for rule in self.export_data["security_applied"]:
                f.write(f"✓ {rule}\n")
        
        print(f"[+] Report saved to: {report_file}")
        return report_file


def main():
    print("=" * 80)
    print("FIREWALL SECURITY EXPORTER AND HARDENING TOOL")
    print("=" * 80)
    print()
    
    # Check if running as root/sudo
    output, rc = subprocess.run(
        "id -u", shell=True, capture_output=True, text=True
    ).stdout.strip()
    
    if output != "0":
        print("[!] Warning: Not running as root. Some operations may require sudo password.")
        print()
    
    exporter = FirewallExporter()
    
    # Export current configurations
    exporter.export_firewalld()
    exporter.export_ufw()
    
    # Apply security hardening
    print("\n" + "=" * 80)
    response = input("Apply security hardening? (yes/no): ").lower()
    
    if response in ['yes', 'y']:
        exporter.apply_firewalld_hardening()
        exporter.apply_ufw_hardening()
    else:
        print("[*] Skipping security hardening")
    
    # Save export and generate report
    print("\n" + "=" * 80)
    exporter.save_export()
    exporter.generate_report()
    
    print("\n[+] Complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
