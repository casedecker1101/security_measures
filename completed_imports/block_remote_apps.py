#!/usr/bin/env python3
import os, platform, subprocess, shlex

apps_remote20 = ["TeamViewer","AnyDesk","Microsoft Remote Desktop (RDP)","Chrome Remote Desktop","LogMeIn Pro","Splashtop","GoToMyPC","RealVNC","UltraVNC","ConnectWise Control (ScreenConnect)","BeyondTrust Remote Support (Bomgar)","Dameware Remote Support","RemotePC by IDrive","Zoho Assist","NoMachine","Citrix Virtual Apps and Desktops","VMware Horizon","Apple Remote Desktop (ARD)","OpenSSH","RustDesk"]
apps_draytek = ["Skype","WhatsApp","Telegram","WeChat","Line","Discord","Facebook","Instagram","TikTok","Twitter","Snapchat","YouTube","Netflix","Twitch","Spotify","Dropbox","Google Drive","OneDrive","Box","Zoom","Webex","Microsoft Teams","Slack","Steam","Epic Games","PlayStation Network","Xbox Live","Tor","Psiphon","PPTP","L2TP","IPsec","OpenVPN","SSL VPNs","FTP","SFTP","BitTorrent","eMule","WireGuard","Shadowsocks","Jitsi Meet"]
apps = sorted(set(apps_remote20 + apps_draytek))

ports_base50 = [22,80,443,3389,3390,3391,5900,5901,5902,5903,5904,5905,5906,5907,5908,5909,5800,5801,5802,5803,5500,5938,5939,6568,3478,5349,19302,19303,19304,19305,19306,19307,19308,19309,5222,6783,8040,8041,6129,4000,1494,2598,4172,8443,3283,21115,21116,50001,50002,6010]
ports_extra50 = [8080,8081,4443,53,123,5353,3479,3480,3481,1935,5223,5228,5229,5230,4244,5224,1080,3128,8088,27015,27036,3074,3659,25565,17500,1194,1701,1723,500,4500,9001,9030,9150,6881,6882,6883,6884,6885,6886,6887,6888,6889,51413,5060,5061,8801,8802,8803,8804,8805]
ports = sorted(set(ports_base50 + ports_extra50))
dry = "--dry-run" in os.sys.argv

def run(cmd):
    print(cmd)
    if not dry:
        subprocess.run(cmd, shell=True, check=False)

def block_linux_like(use_su=False):
    sudo = "" if os.geteuid()==0 else ("su -c " if use_su else "sudo ")
    for p in ports:
        for proto in ("tcp","udp"):
            for tbl in ("iptables","ip6tables"):
                run(f"{sudo}{tbl} -A INPUT  -p {proto} --dport {p} -j REJECT")
                run(f"{sudo}{tbl} -A OUTPUT -p {proto} --dport {p} -j REJECT")

def block_windows():
    port_csv = ",".join(str(p) for p in ports)
    base = 'powershell -NoProfile -NonInteractive -Command '
    rules = [
        f'New-NetFirewallRule -DisplayName "Block-RemoteApps-In-TCP"  -Direction Inbound  -Action Block -Protocol TCP -LocalPort {port_csv}  -Profile Any -Enabled True -ErrorAction SilentlyContinue',
        f'New-NetFirewallRule -DisplayName "Block-RemoteApps-In-UDP"  -Direction Inbound  -Action Block -Protocol UDP -LocalPort {port_csv}  -Profile Any -Enabled True -ErrorAction SilentlyContinue',
        f'New-NetFirewallRule -DisplayName "Block-RemoteApps-Out-TCP" -Direction Outbound -Action Block -Protocol TCP -RemotePort {port_csv} -Profile Any -Enabled True -ErrorAction SilentlyContinue',
        f'New-NetFirewallRule -DisplayName "Block-RemoteApps-Out-UDP" -Direction Outbound -Action Block -Protocol UDP -RemotePort {port_csv} -Profile Any -Enabled True -ErrorAction SilentlyContinue',
    ]
    for r in rules: run(base + '"' + r + '"')

def is_android():
    try:
        return "android" in platform.release().lower() or "ANDROID_ROOT" in os.environ
    except Exception:
        return False

if platform.system()=="Windows":
    block_windows()
elif is_android():
    block_linux_like(use_su=True)
else:
    block_linux_like()

print("Blocked applications (by ports): " + ", ".join(apps))
print("Total ports:", len(ports))
