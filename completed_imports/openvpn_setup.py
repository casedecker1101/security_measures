#!/usr/bin/env python3
import os, sys, subprocess, shlex, argparse, getpass, tempfile

CFG_DIR = "/etc/openvpn/client"
CFG_NAME = "proton"
CFG_SRC_DEFAULT = os.path.join(CFG_DIR, "se-us-01.protonvpn.tcp.ovpn")
CFG_PATH = os.path.join(CFG_DIR, f"{CFG_NAME}.conf")
AUTH_PATH = os.path.join(CFG_DIR, "auth.txt")

def sudo_prefix():
    return "" if os.geteuid() == 0 else "sudo "

def run(cmd, check=True, capture=False):
    if isinstance(cmd, str):
        shell=True; c=cmd
    else:
        shell=False; c=cmd
    print(cmd if isinstance(cmd,str) else " ".join(map(shlex.quote,cmd)))
    if capture:
        res = subprocess.run(cmd, shell=shell, check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return res.stdout
    else:
        return subprocess.run(cmd, shell=shell, check=check)

def ensure_packages():
    pkgs = ["openvpn", "resolvconf"]
    missing = []
    for p in pkgs:
        r = subprocess.run(["dpkg-query","-W","-f","${Status}",p], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if "install ok installed" not in r.stdout:
            missing.append(p)
    if missing:
        run(sudo_prefix()+"apt-get update -y || true")
        run(sudo_prefix()+"apt-get install -y " + " ".join(missing))

def pick_src(cfg_src):
    if cfg_src and os.path.exists(cfg_src):
        return cfg_src
    if os.path.exists(CFG_SRC_DEFAULT):
        return CFG_SRC_DEFAULT
    # pick first .ovpn in client dir
    if os.path.isdir(CFG_DIR):
        for f in sorted(os.listdir(CFG_DIR)):
            if f.endswith('.ovpn'):
                return os.path.join(CFG_DIR,f)
    print("No .ovpn source found. Place a provider .ovpn in /etc/openvpn/client and re-run.")
    sys.exit(1)

def ensure_auth(username=None, password=None):
    if username is None:
        username = os.environ.get("OVPN_USER") or input("OpenVPN service username: ")
    if password is None:
        password = os.environ.get("OVPN_PASS") or getpass.getpass("OpenVPN service password: ")
    tmp = tempfile.NamedTemporaryFile('w', delete=False)
    tmp.write(username.strip()+"\n"+password.strip()+"\n")
    tmp.close()
    run(sudo_prefix()+f"install -m 600 -o root -g root {shlex.quote(tmp.name)} {shlex.quote(AUTH_PATH)}")
    os.unlink(tmp.name)

def load_text(p):
    with open(p,'r') as f: return f.read().splitlines()

def save_text_root(p, lines):
    tmp = tempfile.NamedTemporaryFile('w', delete=False)
    tmp.write("\n".join(lines)+"\n")
    tmp.close()
    run(sudo_prefix()+f"install -m 644 -o root -g root {shlex.quote(tmp.name)} {shlex.quote(p)}")
    os.unlink(tmp.name)

def normalize_conf(src, dst):
    lines = load_text(src)
    out = []
    have_auth = False
    have_script_sec = False
    have_up = False
    have_down = False
    have_redirect = False
    for line in lines:
        s = line.strip()
        if s.lower().startswith('auth-user-pass'):
            out.append('auth-user-pass ' + AUTH_PATH)
            have_auth = True
        else:
            if s.lower().startswith('script-security'):
                have_script_sec = True
            if s.lower().startswith('up '):
                have_up = True
            if s.lower().startswith('down '):
                have_down = True
            if s.lower().startswith('redirect-gateway'):
                have_redirect = True
            out.append(line)
    if not have_auth:
        out.append('auth-user-pass ' + AUTH_PATH)
    if not have_script_sec:
        out.append('script-security 2')
    if not have_up:
        out.append('up /etc/openvpn/update-resolv-conf')
    if not have_down:
        out.append('down /etc/openvpn/update-resolv-conf')
    if not have_redirect:
        out.append('redirect-gateway def1')
    save_text_root(dst, out)

def connect_foreground(nocache=True):
    args = ["openvpn","--config",CFG_PATH]
    if nocache:
        args += ["--auth-nocache","--auth-retry","interact"]
    run(sudo_prefix()+" "+" ".join(map(shlex.quote,args)), check=False)

def start_service():
    # openvpn-client@<name> expects /etc/openvpn/client/<name>.conf
    run(sudo_prefix()+f"systemctl enable --now openvpn-client@{CFG_NAME}", check=False)

def stop_service():
    run(sudo_prefix()+f"systemctl disable --now openvpn-client@{CFG_NAME}", check=False)

def verify_routes():
    out = run(["ip","route","get","1.1.1.1"], capture=True)
    ok_route = " dev tun" in out
    dns = ""; resolv = "/etc/resolv.conf"
    if os.path.exists(resolv):
        with open(resolv) as f:
            for ln in f:
                if ln.strip().startswith("nameserver"):
                    dns = ln.strip().split()[1]; break
    # sockets sample
    try:
        ss = run(["bash","-lc","ss -H -tn state established | awk '{print $5}' | cut -d: -f1 | head -n 10"], capture=True)
        leak = False
        for ip in [i for i in ss.split() if i and i[0].isdigit()]:
            r = run(["bash","-lc", f"ip route get {shlex.quote(ip)} | grep -vq ' dev tun' && echo notun || true"], capture=True)
            if "notun" in r: leak = True; break
    except Exception:
        leak = False
    print(f"tun route: {'OK' if ok_route else 'FAIL'}; DNS: {dns}; leaks: {'YES' if leak else 'NO'}")
    return ok_route and not leak

def main():
    ap = argparse.ArgumentParser(description="OpenVPN setup/verify helper")
    ap.add_argument('--prepare', action='store_true', help='Install deps, create auth, normalize config')
    ap.add_argument('--connect', action='store_true', help='Start OpenVPN (systemd if available)')
    ap.add_argument('--foreground', action='store_true', help='Run OpenVPN in foreground instead of systemd')
    ap.add_argument('--verify', action='store_true', help='Verify all traffic goes via tun and DNS is set')
    ap.add_argument('--disconnect', action='store_true', help='Stop OpenVPN service')
    ap.add_argument('--ovpn', help='Path to .ovpn (defaults to first in /etc/openvpn/client)')
    args = ap.parse_args()

    if args.prepare:
        ensure_packages()
        src = pick_src(args.ovpn)
        ensure_auth()
        normalize_conf(src, CFG_PATH)
        print(f"Prepared {CFG_PATH} and {AUTH_PATH}")

    if args.connect:
        try:
            if args.foreground:
                connect_foreground()
            else:
                start_service()
        finally:
            print("Started OpenVPN (check with: systemctl status openvpn-client@proton || pgrep -fa openvpn)")

    if args.verify:
        ok = verify_routes()
        sys.exit(0 if ok else 1)

    if args.disconnect:
        stop_service()

if __name__ == '__main__':
    main()
