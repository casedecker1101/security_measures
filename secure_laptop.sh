#!/usr/bin/env bash
set -euo pipefail
# secure_laptop.sh
# Idempotent script to configure UFW, Fail2Ban and optionally nftables on Debian/Ubuntu-like systems.
# Usage: sudo ./scripts/secure_laptop.sh [--dry-run] [--non-interactive] [--enable-nft] [--no-ufw]

DRY_RUN=0
NONINTERACTIVE=0
ENABLE_NFT=0
NO_UFW=0
NO_FAIL2BAN=0
ROLLBACK=0
WHITELIST=""
USER_SET_ENABLE_NFT=0
USER_SET_NO_UFW=0

print() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

usage() {
  cat <<EOF
Usage: sudo $0 [--dry-run] [--non-interactive] [--enable-nft] [--no-ufw] [--no-fail2ban]

Options:
  --dry-run         Print actions without making changes
  --non-interactive Do not prompt; assume yes for confirmations
  --enable-nft      Configure basic nftables rules (recommended only if you disable ufw with --no-ufw)
  --no-ufw          Do not configure UFW; useful when you want nftables only
  --no-fail2ban     Skip Fail2Ban setup (useful when focusing on nftables only)

Notes:
  - This script is written to be idempotent and to back up modified configs.
  - Default behavior: configure UFW + Fail2Ban. nftables is optional and should replace UFW if enabled with --no-ufw.
  - Tested on Debian/Ubuntu. On other distros, package manager detection is best-effort.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;; 
    --non-interactive) NONINTERACTIVE=1 ;; 
    --enable-nft) ENABLE_NFT=1; USER_SET_ENABLE_NFT=1 ;; 
  --no-ufw) NO_UFW=1; USER_SET_NO_UFW=1 ;; 
  --no-fail2ban) NO_FAIL2BAN=1 ;;
  --rollback) ROLLBACK=1 ;; 
  --whitelist=*) WHITELIST="${arg#*=}" ;; 
    -h|--help) usage; exit 0 ;; 
    *) err "Unknown arg: $arg"; usage; exit 2 ;;
  esac

done

# Run ID and logging/manifest files
RUN_ID=$(date +%Y%m%d-%H%M%S)
LOG_DIR=/var/log/secure_laptop
mkdir -p "$LOG_DIR"
mkdir -p /var/backups
LOG_FILE="$LOG_DIR/secure_laptop_${RUN_ID}.log"
MANIFEST="$LOG_DIR/backup_manifest_${RUN_ID}.txt"
CREATED_FILES="$LOG_DIR/created_files_${RUN_ID}.txt"
MODIFIED_SERVICES="$LOG_DIR/modified_services_${RUN_ID}.txt"
touch "$MANIFEST" "$CREATED_FILES" "$MODIFIED_SERVICES"

# Absolute path to this script
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]:-$0}")

run_cmd() {
  # Accepts the command and arguments; preserves spaces/redirects.
  local cmd
  cmd="$*"
  if [ "${DRY_RUN:-0}" -eq 1 ]; then
    print "DRY-RUN: $cmd"
    return 0
  fi

  print "+ $cmd"

  # Temporarily disable errexit so callers can use 'run_cmd ... || true'
  set +e
  bash -c "$cmd"
  local rc=$?
  # Restore errexit
  set -e

  if [ $rc -ne 0 ]; then
    err "Command failed (rc=$rc): $cmd"
  fi
  return $rc
}

backup_file() {
  local f="$1"
  if [ -e "$f" ]; then
    local now dest rc
    now=$(date +%Y%m%d-%H%M%S)
    dest="${f}.bak-$now"
    print "Backing up $f -> $dest"
    run_cmd cp -a "$f" "$dest"
    rc=$?

    # Record the original and backup pair in the manifest for rollback
    if [ "${DRY_RUN:-0}" -eq 0 ] && [ "$rc" -eq 0 ]; then
      touch "${MANIFEST:-/dev/null}" >/dev/null 2>&1 || true
      echo "${f}|${dest}" >> "${MANIFEST:-/dev/null}"
    fi
  fi
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    echo apt
  elif command -v dnf >/dev/null 2>&1; then
    echo dnf
  elif command -v pacman >/dev/null 2>&1; then
    echo pacman
  else
    echo unknown
  fi
}

detect_distro() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "${ID:-unknown}" "${ID_LIKE:-}"
  else
    echo "unknown"
  fi
}

# Default to nftables-only on Arch unless user explicitly chose otherwise.
if [ "$USER_SET_ENABLE_NFT" -eq 0 ] && [ "$USER_SET_NO_UFW" -eq 0 ]; then
  distro_info=$(detect_distro)
  if echo "$distro_info" | grep -qi "\barch\b"; then
    ENABLE_NFT=1
    NO_UFW=1
    print "Detected Arch; defaulting to nftables-only mode"
  fi
fi

systemd_available() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 1
  fi
  # Most reliable indicator for systemd being PID 1.
  if [ -d /run/systemd/system ]; then
    return 0
  fi
  # Fall back to systemctl's own check if available.
  systemctl is-system-running --quiet >/dev/null 2>&1
}

disable_firewalld() {
  if ! systemd_available; then
    return 0
  fi
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    print "Disabling firewalld to avoid conflicts with nftables"
    run_cmd systemctl disable --now firewalld || true
  fi
}

ensure_nft_table() {
  local table="$1"
  if nft list table inet "$table" >/dev/null 2>&1; then
    return 0
  fi
  run_cmd nft add table inet "$table" || return 1
  run_cmd nft add chain inet "$table" input '{ type filter hook input priority -100; policy accept; }'
}

ensure_package() {
  local pkg="$1"
  local mgr
  mgr=$(detect_pkg_mgr)
  case "$mgr" in
    apt)
      if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        run_cmd apt-get update
        run_cmd DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
      else
        print "$pkg already installed"
      fi
      ;;
    dnf)
      if ! rpm -q "$pkg" >/dev/null 2>&1; then
        run_cmd dnf install -y "$pkg"
      else
        print "$pkg already installed"
      fi
      ;;
    pacman)
      if ! pacman -Qi "$pkg" >/dev/null 2>&1; then
        run_cmd pacman -S --noconfirm "$pkg"
      else
        print "$pkg already installed"
      fi
      ;;
    *)
      err "Unsupported package manager: $mgr. Please install $pkg manually."
      ;;
  esac
}

# Add deny rules for RFC1918 and ULA local subnets
add_deny_local_subnets() {
  print "Adding deny rules for local subnets (RFC1918/ULA)"
  local ipv4_nets=("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")
  local ipv6_nets=("fc00::/7")
  local nft_table=""

  # UFW: add explicit allow for whitelist then deny rules (backed up earlier)
  if [ "$NO_UFW" -eq 0 ]; then
    # apply whitelist first
    if [ -n "$WHITELIST" ]; then
      IFS=',' read -ra WCLS <<< "$WHITELIST"
      for w in "${WCLS[@]}"; do
        run_cmd ufw allow in from "$w" to any comment 'whitelist'
      done
      print "Applied whitelist: $WHITELIST"
    fi
    for n in "${ipv4_nets[@]}"; do
      run_cmd ufw deny in from "$n" to any comment 'deny-rfc1918'
    done
    for n in "${ipv6_nets[@]}"; do
      run_cmd ufw deny in from "$n" to any comment 'deny-ula'
    done
  fi

  # nftables: only add runtime rules when nft is explicitly enabled
  if [ "$ENABLE_NFT" -eq 1 ] && command -v nft >/dev/null 2>&1; then
    if nft list table inet filter >/dev/null 2>&1; then
      nft_table="filter"
    else
      nft_table="secure_laptop"
      ensure_nft_table "$nft_table" || return 0
    fi
    # nft whitelist
    if [ -n "$WHITELIST" ]; then
      IFS=',' read -ra WCLS <<< "$WHITELIST"
      for w in "${WCLS[@]}"; do
        run_cmd nft add rule inet "$nft_table" input iifname != lo ip saddr "$w" accept || true
      done
      print "Applied nft whitelist: $WHITELIST"
    fi
    for n in "${ipv4_nets[@]}"; do
      run_cmd nft add rule inet "$nft_table" input iifname != lo ip saddr "$n" drop || true
    done
    for n in "${ipv6_nets[@]}"; do
      run_cmd nft add rule inet "$nft_table" input iifname != lo ip6 saddr "$n" drop || true
    done
  else
    # Fallback to iptables/ip6tables and create removal script for rollback
    local add_script=/usr/local/sbin/secure_laptop_iptables_add_${RUN_ID}.sh
    local rm_script=/usr/local/sbin/secure_laptop_iptables_rm_${RUN_ID}.sh
    cat > /tmp/secure_laptop_iptables_add <<'EOF'
#!/usr/bin/env bash
set -e
EOF
    cat > /tmp/secure_laptop_iptables_rm <<'EOF'
#!/usr/bin/env bash
set -e
EOF
    # apply whitelist for iptables if present
    if [ -n "$WHITELIST" ]; then
      IFS=',' read -ra WCLS <<< "$WHITELIST"
      for w in "${WCLS[@]}"; do
        echo "iptables -I INPUT 1 -s $w -j ACCEPT" >> /tmp/secure_laptop_iptables_add
        echo "iptables -D INPUT -s $w -j ACCEPT" >> /tmp/secure_laptop_iptables_rm
      done
    fi
    for n in "${ipv4_nets[@]}"; do
      echo "iptables -I INPUT 1 ! -i lo -s $n -j DROP" >> /tmp/secure_laptop_iptables_add
      echo "iptables -D INPUT ! -i lo -s $n -j DROP" >> /tmp/secure_laptop_iptables_rm
    done
    for n in "${ipv6_nets[@]}"; do
      echo "ip6tables -I INPUT 1 ! -i lo -s $n -j DROP" >> /tmp/secure_laptop_iptables_add
      echo "ip6tables -D INPUT ! -i lo -s $n -j DROP" >> /tmp/secure_laptop_iptables_rm
    done
    run_cmd mv /tmp/secure_laptop_iptables_add "$add_script"
    run_cmd mv /tmp/secure_laptop_iptables_rm "$rm_script"
    run_cmd chmod 0755 "$add_script" "$rm_script"
    echo "$add_script" >> "${CREATED_FILES:-/dev/null}"
    echo "$rm_script" >> "${CREATED_FILES:-/dev/null}"
    # run add script
    run_cmd "$add_script"
  fi
}


confirm() {
  if [ "$NONINTERACTIVE" -eq 1 ]; then
    return 0
  fi
  read -r -p "$1 [y/N]: " ans || return 1
  case "$ans" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *) return 1 ;;
  esac
}

if [ "$EUID" -ne 0 ]; then
  err "This script should be run as root. Use sudo."; exit 1
fi

print "Starting secure_laptop.sh"

# Setup run log and manifests
RUN_ID=$(date +%Y%m%d-%H%M%S)
LOG_DIR=/var/log/secure_laptop
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/secure_laptop_${RUN_ID}.log"
MANIFEST="$LOG_DIR/backup_manifest_${RUN_ID}.txt"
CREATED_FILES="$LOG_DIR/created_files_${RUN_ID}.txt"
MODIFIED_SERVICES="$LOG_DIR/modified_services_${RUN_ID}.txt"
touch "$MANIFEST" "$CREATED_FILES" "$MODIFIED_SERVICES"
exec > >(tee -a "$LOG_FILE") 2>&1

# Exit handler to analyze logs and print final status
EXIT_STATUS=0
on_exit() {
  EXIT_STATUS=$?
  print "\n--- Run summary ---"
  print "Log file: $LOG_FILE"

  # Only treat explicit script errors as failure
  if grep -E "^ERROR: |Command failed" "$LOG_FILE" >/dev/null 2>&1; then
    print "Failed completion - review logs"
    # add some journal hints
    if command -v journalctl >/dev/null 2>&1; then
      print "Recent journal errors (last 200 lines):"
      journalctl -p err -n 200 --no-pager || true
    fi
    exit 1
  fi

  if [ "$EXIT_STATUS" -ne 0 ]; then
    print "Script exited with status $EXIT_STATUS"
    exit "$EXIT_STATUS"
  fi

  print "Completed successfully"
  exit 0
}
trap on_exit EXIT

# Determine SSH port (if configured)
SSHD_PORT=22
if [ -r /etc/ssh/sshd_config ]; then
  portline=$(grep -Ei '^\s*Port\s+' /etc/ssh/sshd_config || true)
  if [ -n "$portline" ]; then
    # take last configured Port if multiple
    SSHD_PORT=$(echo "$portline" | awk '{print $2}' | tail -n1)
  fi
fi

print "Detected SSH port: $SSHD_PORT"

# If user asked for nftables-only but not enabling nft, warn
if [ "$NO_UFW" -eq 1 ] && [ "$ENABLE_NFT" -eq 0 ]; then
  print "Warning: --no-ufw used without --enable-nft. This will leave no firewall unless another is configured."
  if ! confirm "Continue anyway?"; then
    print "Aborting."; exit 1
  fi
fi

if [ "$NO_UFW" -eq 0 ]; then
  # Install and configure UFW
  print "Configuring UFW (uncomplicated firewall)"
  ensure_package ufw || true

  # Back up UFW config
  backup_file /etc/ufw/ufw.conf
  backup_file /etc/ufw/before.rules || true
  backup_file /etc/ufw/after.rules || true

  # Basic UFW defaults
  run_cmd ufw --force default deny incoming
  run_cmd ufw --force default allow outgoing

  # Allow loopback
  run_cmd ufw allow in on lo

  # Allow SSH (detected port) and rate limit
  if [ "$SSHD_PORT" = "22" ]; then
    run_cmd ufw limit ssh
  else
    run_cmd ufw allow "$SSHD_PORT"/tcp
    run_cmd ufw limit "$SSHD_PORT"/tcp
  fi

  # Allow mDNS and DHCP for typical laptops (optional but useful)
  run_cmd ufw allow 5353/udp comment 'mDNS'
  run_cmd ufw allow 67/udp comment 'DHCP'

  # Enable logging at medium level
  run_cmd ufw logging medium

  # Enable UFW
  run_cmd ufw --force enable

  # Deny incoming from RFC1918 private address ranges (local subnets)
  PRIVATE_RANGES=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
  for r in "${PRIVATE_RANGES[@]}"; do
    # insert at top to ensure it's evaluated early
    run_cmd ufw insert 1 deny from "$r" to any
  done

  # Protect loopback against spoofing using nft/iptables with rollback scripts
  protect_loopback() {
    local add_script=/usr/local/sbin/secure_laptop_loopback_add_${RUN_ID}.sh
    local rm_script=/usr/local/sbin/secure_laptop_loopback_rm_${RUN_ID}.sh

    cat > /tmp/secure_laptop_loopback_add <<'EOF'
#!/usr/bin/env bash
set -e
if command -v nft >/dev/null 2>&1; then
  if nft list table inet secure_laptop >/dev/null 2>&1; then
    nft flush table inet secure_laptop
  else
    nft add table inet secure_laptop
    nft add chain inet secure_laptop input '{ type filter hook input priority -100; policy accept; }'
  fi
  nft add rule inet secure_laptop input iifname lo accept
  nft add rule inet secure_laptop input iifname != lo ip saddr 127.0.0.0/8 drop
  nft add rule inet secure_laptop input iifname != lo ip6 saddr ::1 drop
else
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT 1 -i lo -j ACCEPT
    iptables -C INPUT ! -i lo -s 127.0.0.0/8 -j DROP >/dev/null 2>&1 || iptables -I INPUT 2 ! -i lo -s 127.0.0.0/8 -j DROP
  fi
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 || ip6tables -I INPUT 1 -i lo -j ACCEPT
    ip6tables -C INPUT ! -i lo -s ::1 -j DROP >/dev/null 2>&1 || ip6tables -I INPUT 2 ! -i lo -s ::1 -j DROP
  fi
fi
EOF

    cat > /tmp/secure_laptop_loopback_rm <<'EOF'
#!/usr/bin/env bash
set -e
if command -v nft >/dev/null 2>&1; then
  if nft list table inet secure_laptop >/dev/null 2>&1; then
    nft delete table inet secure_laptop
  fi
fi
if command -v iptables >/dev/null 2>&1; then
  iptables -D INPUT ! -i lo -s 127.0.0.0/8 -j DROP >/dev/null 2>&1 || true
  iptables -D INPUT -i lo -j ACCEPT >/dev/null 2>&1 || true
fi
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -D INPUT ! -i lo -s ::1 -j DROP >/dev/null 2>&1 || true
  ip6tables -D INPUT -i lo -j ACCEPT >/dev/null 2>&1 || true
fi
EOF

    run_cmd mv /tmp/secure_laptop_loopback_add "$add_script"
    run_cmd mv /tmp/secure_laptop_loopback_rm "$rm_script"
    run_cmd chmod 0755 "$add_script" "$rm_script"
    echo "$add_script" >> "${CREATED_FILES:-/dev/null}"
    echo "$rm_script" >> "${CREATED_FILES:-/dev/null}"
    run_cmd "$add_script"
  }
  protect_loopback

  print "UFW status:"
  run_cmd ufw status verbose || true
  # Deny typical local subnets to avoid spoofing/inbound local net vectors
  add_deny_local_subnets
fi

if [ "$NO_UFW" -eq 1 ] && command -v ufw >/dev/null 2>&1; then
  print "UFW disabled (nftables-only mode)"
  run_cmd ufw --force disable || true
fi

# Install and configure Fail2Ban (optional)
if [ "$NO_FAIL2BAN" -eq 0 ]; then
  print "Configuring Fail2Ban"
  ensure_package fail2ban || true

  F2B_JAIL_DIR=/etc/fail2ban/jail.d
  F2B_CONF_FILE=${F2B_JAIL_DIR}/secure_laptop.conf

  backup_file "$F2B_CONF_FILE"

  # Choose action based on availability of nft
  if command -v nft >/dev/null 2>&1; then
    F2B_ACTION=nftables
  else
    F2B_ACTION=ufw
  fi

  [ -n "${F2B_ACTION:-}" ] || F2B_ACTION=ufw
  print "Selected fail2ban action: $F2B_ACTION"

  # Choose recidive logpath: prefer fail2ban log, else auth/secure, else create fail2ban log
  RECIDIVE_LOGPATH="/var/log/fail2ban.log"
  if [ -e /var/log/fail2ban.log ]; then
    RECIDIVE_LOGPATH="/var/log/fail2ban.log"
  elif [ -e /var/log/auth.log ]; then
    RECIDIVE_LOGPATH="/var/log/auth.log"
  elif [ -e /var/log/secure ]; then
    RECIDIVE_LOGPATH="/var/log/secure"
  else
    RECIDIVE_LOGPATH="/var/log/fail2ban.log"
    # create the file (run_cmd respects dry-run)
    run_cmd touch "$RECIDIVE_LOGPATH"
    run_cmd chown root:adm "$RECIDIVE_LOGPATH" || true
    run_cmd chmod 0640 "$RECIDIVE_LOGPATH" || true
  fi

  cat > /tmp/secure_laptop_f2b.conf <<EOF
[sshd]
enabled = true
port = $SSHD_PORT
filter = sshd
logpath = %(sshd_log)s
maxretry = 5
bantime = 600
findtime = 600
action = $F2B_ACTION

[recidive]
enabled = true
logpath = $RECIDIVE_LOGPATH
action = $F2B_ACTION
bantime = 86400
findtime = 86400
EOF

  run_cmd mkdir -p "$F2B_JAIL_DIR"
  run_cmd mv /tmp/secure_laptop_f2b.conf "$F2B_CONF_FILE"
  echo "$F2B_CONF_FILE" >> "${CREATED_FILES:-/dev/null}"

  # Extra aggressive jails for remote access/screencast/audio/video/thumbnailer/sslh
  F2B_EXTRA_FILTER=/etc/fail2ban/filter.d/secure-laptop-auth.conf
  F2B_EXTRA_JAIL=/etc/fail2ban/jail.d/secure_laptop-extra.local
  F2B_DISABLE_JAIL=/etc/fail2ban/jail.d/zzz-secure_laptop-disable-invalid.conf
  F2B_JAILS_LOCAL=/etc/fail2ban/jails.local
  F2B_JAILS_LOCAL_D=/etc/fail2ban/jail.d/jails.local

  cat > /tmp/secure_laptop_auth_filter.conf <<'EOF'
[Definition]
failregex = (?i)^.*(authentication|login|auth).*?(failed|failure|invalid|denied).*?(from|rhost=|host=|ip=)\s*<HOST>.*$
            (?i)^.*Failed .*?(from|rhost=|host=|ip=)\s*<HOST>.*$
ignoreregex =
EOF

  run_cmd mv /tmp/secure_laptop_auth_filter.conf "$F2B_EXTRA_FILTER"
  echo "$F2B_EXTRA_FILTER" >> "${CREATED_FILES:-/dev/null}"

  cat > /tmp/secure_laptop_extra_jails.conf <<EOF
[DEFAULT]
bantime = -1
findtime = 1m
maxretry = 1

# SSH: instant/eternal
[sshd]
enabled = true
port = $SSHD_PORT
action = $F2B_ACTION

# SSLH
[secure-laptop-sslh]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=sslh.service
action = $F2B_ACTION

# Remote desktop (GNOME)
[secure-laptop-remote-desktop]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=gnome-remote-desktop.service
action = $F2B_ACTION

[secure-laptop-remote-desktop-shell]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=gnome-shell-remote-desktop.service
action = $F2B_ACTION

# Screencasting / portals
[secure-laptop-screencast-portal]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=xdg-desktop-portal.service
action = $F2B_ACTION

[secure-laptop-screencast-portal-gnome]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=xdg-desktop-portal-gnome.service
action = $F2B_ACTION

# Audio/video stacks
[secure-laptop-audio-pulseaudio]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=pulseaudio.service
action = $F2B_ACTION

[secure-laptop-audio-pipewire]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=pipewire.service
action = $F2B_ACTION

[secure-laptop-audio-wireplumber]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=wireplumber.service
action = $F2B_ACTION

# Thumbnailers
[secure-laptop-thumbnailer-tumblerd]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=tumblerd.service
action = $F2B_ACTION

[secure-laptop-thumbnailer-tracker]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=tracker-miner-fs.service
action = $F2B_ACTION

[secure-laptop-thumbnailer-gnome]
enabled = true
filter = secure-laptop-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=gnome-desktop-thumbnailer.service
action = $F2B_ACTION
EOF

  run_cmd mv /tmp/secure_laptop_extra_jails.conf "$F2B_EXTRA_JAIL"
  echo "$F2B_EXTRA_JAIL" >> "${CREATED_FILES:-/dev/null}"

  cat > /tmp/secure_laptop_disable_jails.conf <<'EOF'
[apache-common]
enabled = false

[nginx-error-common]
enabled = false
EOF

  run_cmd mv /tmp/secure_laptop_disable_jails.conf "$F2B_DISABLE_JAIL"
  echo "$F2B_DISABLE_JAIL" >> "${CREATED_FILES:-/dev/null}"

  # Remove invalid include-only jails that reference filters without [Definition]
  remove_invalid_f2b_jails() {
    local f="$1"
    [ -f "$f" ] || return 0

    backup_file "$f"

    local tmp
    tmp="/tmp/secure_laptop_f2b_jails_$(basename "$f").tmp"
    awk '
      BEGIN {
        skip = 0
        bad["apache-common"] = 1
        bad["nginx-error-common"] = 1
      }
      /^\[/ {
        sec = $0
        gsub(/^\[/, "", sec)
        gsub(/\]$/, "", sec)
        skip = (sec in bad)
      }
      {
        if (!skip) print
      }
    ' "$f" > "$tmp"

    run_cmd mv "$tmp" "$f"
  }

  remove_invalid_f2b_jails "$F2B_JAILS_LOCAL"
  remove_invalid_f2b_jails "$F2B_JAILS_LOCAL_D"

  # Restart fail2ban (if nftables action is used, restart again after nftables is up)
  if command -v systemctl >/dev/null 2>&1; then
    run_cmd systemctl restart fail2ban || run_cmd service fail2ban restart || true
  else
    run_cmd service fail2ban restart || true
  fi

  print "Fail2Ban status (summary):"
  if ! fail2ban-client status; then
    print "Fail2Ban status check failed (non-fatal)"
  fi
else
  print "Skipping Fail2Ban setup (--no-fail2ban)"
fi

# Optional nftables configuration
if [ "$ENABLE_NFT" -eq 1 ]; then
  if [ "$NO_UFW" -eq 0 ]; then
    print "Warning: enabling nftables while UFW is active can cause conflicts. It's recommended to use nftables only if you disable UFW (--no-ufw)."
    if ! confirm "Continue enabling nftables alongside UFW?"; then
      print "Skipping nftables configuration.";
      ENABLE_NFT=0
    fi
  fi
fi

if [ "$ENABLE_NFT" -eq 1 ]; then
  print "Configuring basic nftables ruleset"
  ensure_package nftables || true
  disable_firewalld

  backup_file /etc/nftables.conf
  run_cmd nft flush table inet filter || true

  cat > /tmp/secure_laptop_nft.conf <<'NFT'
#!/usr/sbin/nft -f
table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;

    # allow loopback
    iif lo accept

  # protect against loopback spoofing
  ip saddr 127.0.0.0/8 iifname != lo drop
  ip6 saddr ::1 iifname != lo drop

    # allow established/related
    ct state established,related accept

    # deny incoming from local subnets (RFC1918) and IPv6 ULA
    ip saddr {10.0.0.0/8,172.16.0.0/12,192.168.0.0/16} ct state new drop
    ip6 saddr fc00::/7 ct state new drop

    # allow ICMP (useful for diagnostics)
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # allow SSH (templated by script)
    tcp dport 22 ct state new,established accept

    # allow DHCP client
    udp sport 68 udp dport 68 accept
  }

  chain forward { type filter hook forward priority 0; policy drop; }

  chain output { type filter hook output priority 0; policy accept; }
}
NFT

  # Replace SSH port placeholder if needed
  if [ "$SSHD_PORT" != "22" ]; then
    sed "s/tcp dport 22/tcp dport $SSHD_PORT/" /tmp/secure_laptop_nft.conf > /tmp/secure_laptop_nft.conf.tmp && mv /tmp/secure_laptop_nft.conf.tmp /tmp/secure_laptop_nft.conf
  fi

  run_cmd mv /tmp/secure_laptop_nft.conf /etc/nftables.conf
  echo "/etc/nftables.conf" >> "${CREATED_FILES:-/dev/null}"
  # Load ruleset immediately to ensure runtime tables exist
  run_cmd nft -f /etc/nftables.conf || true
  if systemd_available; then
    run_cmd systemctl enable --now nftables || true
  elif command -v service >/dev/null 2>&1; then
    run_cmd service nftables start || true
  fi
  run_cmd nft list ruleset || true

  if [ "$NO_FAIL2BAN" -eq 0 ] && [ "${F2B_ACTION:-}" = "nftables" ]; then
    if command -v systemctl >/dev/null 2>&1; then
      run_cmd systemctl restart fail2ban || run_cmd service fail2ban restart || true
    else
      run_cmd service fail2ban restart || true
    fi
  fi
fi

print "All done. Summary and next steps:"
if [ "$DRY_RUN" -eq 1 ]; then
  print "Script ran in DRY-RUN mode; no persistent changes made."
else
  print "UFW: $(ufw status verbose 2>/dev/null || echo 'not configured')"
  if [ "$NO_FAIL2BAN" -eq 0 ]; then
    print "Fail2Ban: $(fail2ban-client status 2>/dev/null || echo 'not running')"
  else
    print "Fail2Ban: skipped"
  fi
  if [ "$ENABLE_NFT" -eq 1 ]; then
    print "nftables: OK (ruleset shown above)"
  fi
fi

## Hardening init/system and generator scripts/folders
GENERATOR_PATHS=(
  /usr/lib/systemd/system-generators
  /usr/lib/systemd/system
  /etc/systemd/system
  /etc/init.d
  /etc/init
  /usr/local/bin
  /opt
)

harden_path() {
  local p="$1"
  if [ -e "$p" ]; then
    print "Hardening $p"
    # Backup any permissions and ownership info
    run_cmd getfacl -R "$p" > "/var/backups/secure_laptop_$(basename "$p")_facl_$(date +%Y%m%d-%H%M%S)" || true

    # Set directories to 0755 and files to 0644, unless executable
    run_cmd find "$p" -type d -exec chmod 0755 {} + || true
    run_cmd find "$p" -type f -exec chmod 0644 {} + || true
    run_cmd find "$p" -type f -executable -exec chmod 0755 {} + || true

    # Make sure root owns them
    run_cmd chown -R root:root "$p" || true

    # Prevent write by group/others where not necessary
    run_cmd chmod -R go-w "$p" || true
  else
    print "Path not present: $p"
  fi
}

harden_generators() {
  print "Securing generator and init folders"
  for p in "${GENERATOR_PATHS[@]}"; do
    harden_path "$p"
  done

  # Restrict systemd unit directories further
  if [ -d /etc/systemd/system ]; then
    print "Restricting /etc/systemd/system contents"
    # unit files should be 0644 and owned by root
    run_cmd find /etc/systemd/system -maxdepth 2 -type f -name '*.service' -exec chmod 0644 {} + || true
    run_cmd chown -R root:root /etc/systemd/system || true
  fi

  # Prevent accidental execution of generator scripts by non-root
  if [ -d /usr/lib/systemd/system-generators ]; then
    run_cmd chmod -R 0755 /usr/lib/systemd/system-generators || true
    run_cmd chown -R root:root /usr/lib/systemd/system-generators || true
  fi

  # Optionally remove execute bits from any scripts in /etc/init unless needed
  if [ -d /etc/init ]; then
    run_cmd find /etc/init -type f -name '*.conf' -exec chmod 0644 {} + || true
  fi
}

# Install a systemd service+timer to run the hardening periodically
install_generator_timer() {
  if ! systemd_available; then
    print "systemd not available; skipping timer/service installation"
    return 0
  fi

  local svc=/etc/systemd/system/secure-laptop-generator-harden.service
  local timer=/etc/systemd/system/secure-laptop-generator-harden.timer

  backup_file "$svc"
  backup_file "$timer"

  cat > /tmp/secure-laptop-generator-harden.service <<EOF
[Unit]
Description=Secure laptop - harden generator and init paths
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/env bash -c '/usr/bin/secure-laptop-runner || true'
EOF

  cat > /tmp/secure-laptop-generator-harden.timer <<EOF
[Unit]
Description=Run secure-laptop-generator-harden daily

[Timer]
OnBootSec=5min
OnUnitActiveSec=24h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  # Create a small wrapper script that calls this script's harden function
  local wrapper=/usr/bin/secure-laptop-runner
  backup_file "$wrapper"
  # Ensure the main script is available at /usr/local/sbin so the timer can call it
  run_cmd mkdir -p /usr/local/sbin
  run_cmd cp -a "$SCRIPT_PATH" /usr/local/sbin/secure_laptop.sh
  run_cmd chmod 0755 /usr/local/sbin/secure_laptop.sh

  cat > /tmp/secure-laptop-runner <<'WRAP'
#!/usr/bin/env bash
set -e
exec /usr/local/sbin/secure_laptop.sh --non-interactive || true
WRAP

  run_cmd mv /tmp/secure-laptop-generator-harden.service "$svc"
  echo "$svc" >> "${CREATED_FILES:-/dev/null}"
  run_cmd mv /tmp/secure-laptop-generator-harden.timer "$timer"
  echo "$timer" >> "${CREATED_FILES:-/dev/null}"
  run_cmd mv /tmp/secure-laptop-runner "$wrapper"
  echo "$wrapper" >> "${CREATED_FILES:-/dev/null}"
  run_cmd chmod 0755 "$wrapper"

  run_cmd systemctl daemon-reload
  run_cmd systemctl enable --now secure-laptop-generator-harden.timer || true
}

# Run hardening now and install timer
harden_generators
install_generator_timer

# Disable services, timers, streaming and recording services
disable_service_and_timer() {
  local svc="$1"
  if ! systemd_available; then
    print "systemd not available; skipping disable/mask for $svc"
    return 0
  fi
  if systemctl list-unit-files --type=service | grep -q "^${svc}.service"; then
    print "Disabling service: $svc"
    run_cmd systemctl disable --now "${svc}.service" || run_cmd systemctl stop "${svc}.service" || true
  fi
  if systemctl list-timers --all | grep -q "${svc}"; then
    print "Masking timer: $svc"
    run_cmd systemctl disable --now "${svc}.timer" || true
  fi
  # Mask to prevent activation
  echo "$svc" >> "${MODIFIED_SERVICES:-/dev/null}"
  run_cmd systemctl mask "${svc}.service" || true
}

disable_common_servers() {
  print "Disabling common server services"
  local servers=(
    apache2
    httpd
    nginx
    smb
    smbd
    nfs-server
    rpcbind
    postfix
    dovecot
    mysql
    mariadb
    postgresql
    vsftpd
    telnet.socket
    xinetd
  )
  for s in "${servers[@]}"; do
    disable_service_and_timer "$s"
  done
}

disable_streaming_and_recording() {
  print "Disabling common streaming and desktop-recording services"
  local streaming=(
    pulseaudio
    pipewire
    pipewire-pulse
    spotify
    snap.spotify
    redshift
  )
  local recording=(
    screencast
    obs
    obs-studio
    gnome-shell-remote-desktop
    vino
    x11vnc
  )
  for s in "${streaming[@]}" "${recording[@]}"; do
    disable_service_and_timer "$s" || true
  done
}

# Tighten nftables to minimal incoming exposure while allowing outgoing
tighten_nftables() {
  if ! command -v nft >/dev/null 2>&1; then
    print "nft not available; skipping nft tightening"
    return 0
  fi

  print "Applying tightened nftables ruleset"
  backup_file /etc/nftables.conf
  run_cmd nft flush table inet filter || true

  cat > /tmp/secure_laptop_nft_tight.conf <<'NFT'
#!/usr/sbin/nft -f
table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;

    # lo accepted
    iif lo accept

    # allow established/related
    ct state established,related accept

    # allow ICMP (rate-limited)
    ip protocol icmp limit rate 10/second accept
    ip6 nexthdr icmpv6 limit rate 10/second accept

  # deny incoming from local subnets (RFC1918) and IPv6 ULA
  ip saddr {10.0.0.0/8,172.16.0.0/12,192.168.0.0/16} ct state new drop
  ip6 saddr fc00::/7 ct state new drop

    # allow SSH only from known networks or limited to the port
    tcp dport 22 ct state new limit rate 10/minute accept

    # allow DNS responses for outgoing queries
    udp sport 53 ct state established accept
    udp dport 53 ct state new limit rate 20/second accept

    # allow DHCP client
    udp sport 68 udp dport 68 accept

    # Explicitly drop obvious exploit vectors
    tcp flags & (syn|fin) == (syn|fin) drop
    tcp option maxseg size set 1452
  }

  chain forward { type filter hook forward priority 0; policy drop; }

  chain output { type filter hook output priority 0; policy accept; }
}
NFT

  run_cmd mv /tmp/secure_laptop_nft_tight.conf /etc/nftables.conf
  echo "/etc/nftables.conf" >> "${CREATED_FILES:-/dev/null}"
  # Load tightened ruleset even if service restart fails
  run_cmd nft -f /etc/nftables.conf || true
  run_cmd systemctl restart nftables || run_cmd service nftables restart || true
  run_cmd nft list ruleset || true
}

# Execute disabling and nft tightening
disable_common_servers
disable_streaming_and_recording
tighten_nftables

# Define helper functions before they're invoked below
install_logrotate_config() {
  local lr=/etc/logrotate.d/secure_laptop
  backup_file "$lr"
  cat > /tmp/secure_laptop_logrotate <<'LR'
/var/log/secure_laptop/*.log {
  daily
  rotate 14
  compress
  delaycompress
  missingok
  notifempty
  create 0640 root adm
  sharedscripts
}
LR
  run_cmd mv /tmp/secure_laptop_logrotate "$lr"
  echo "$lr" >> "${CREATED_FILES:-/dev/null}"
}

check_components() {
  local errs=0
  print "Checking component status"
  # UFW check
  if [ "$NO_UFW" -eq 0 ]; then
    if command -v ufw >/dev/null 2>&1; then
      local ustat
      ustat=$(ufw status 2>/dev/null | head -n1 || true)
      if echo "$ustat" | grep -qi active; then
        print "UFW: OK ($ustat)"
      else
        print "ERROR: UFW not active: $ustat"; errs=$((errs+1))
      fi
    else
      print "ERROR: ufw not installed"; errs=$((errs+1))
    fi
  else
    print "UFW: skipped";
  fi

  # Fail2Ban check
  if [ "$NO_FAIL2BAN" -eq 0 ]; then
    if command -v fail2ban-client >/dev/null 2>&1; then
      if (systemd_available && systemctl is-active --quiet fail2ban 2>/dev/null) || service fail2ban status >/dev/null 2>&1; then
        if fail2ban-client status 2>/dev/null | grep -q 'sshd'; then
          print "Fail2Ban: OK (sshd jail present)"
        else
          print "ERROR: Fail2Ban running but sshd jail missing"; errs=$((errs+1))
        fi
      else
        print "ERROR: Fail2Ban not running"; errs=$((errs+1))
      fi
    else
      if [ "$DRY_RUN" -eq 1 ]; then
        print "Skip: fail2ban not installed (dry-run)"
      else
        print "ERROR: fail2ban not installed"; errs=$((errs+1))
      fi
    fi
  else
    print "Fail2Ban: skipped"
  fi

  # nftables check
  if [ "$ENABLE_NFT" -eq 1 ]; then
    if command -v nft >/dev/null 2>&1; then
      if nft list ruleset 2>/dev/null | grep -Eq 'table inet (filter|secure_laptop)'; then
        print "nftables: OK"
      else
        print "ERROR: nftables ruleset missing"; errs=$((errs+1))
      fi
    else
      if [ "$DRY_RUN" -eq 1 ]; then
        print "Skip: nft not installed (dry-run)"
      else
        print "ERROR: nft not installed"; errs=$((errs+1))
      fi
    fi
  else
    print "nftables: not enabled"
  fi

  if [ "$errs" -gt 0 ]; then
    print "Component check found $errs issue(s)"
  else
    print "Component check: all OK"
  fi
}

install_logrotate_config
check_components

rollback_changes() {
  print "Starting rollback..."
  local manifest
  manifest=$(ls -1t "$LOG_DIR"/backup_manifest_*.txt 2>/dev/null | head -n1 || true)
  if [ -z "$manifest" ]; then
    print "No backup manifest found in $LOG_DIR. Nothing to restore."; exit 1
  fi
  print "Using manifest: $manifest"
  while IFS='|' read -r orig backup; do
    if [ -z "$orig" ] || [ -z "$backup" ]; then continue; fi
    if [ -e "$backup" ]; then
      print "Restoring $orig from $backup"
      run_cmd cp -a "$backup" "$orig"
    else
      print "Backup not found: $backup. Skipping $orig"
    fi
  done < "$manifest"

  # restore modified services
  local modfile
  modfile=$(ls -1t "$LOG_DIR"/modified_services_*.txt 2>/dev/null | head -n1 || true)
  if [ -n "$modfile" ]; then
    while read -r s; do
      if [ -n "$s" ]; then
        print "Unmasking and enabling $s"
        run_cmd systemctl unmask "${s}.service" || true
        run_cmd systemctl enable --now "${s}.service" || true
      fi
    done < "$modfile"
  fi

  # run removal scripts and then remove created files
  local created
  created=$(ls -1t "$LOG_DIR"/created_files_*.txt 2>/dev/null | head -n1 || true)
  if [ -n "$created" ]; then
    while read -r f; do
      if [ -n "$f" ] && [ -e "$f" ]; then
        case "$f" in
          *_rm_*.sh)
            print "Executing rollback script: $f"
            run_cmd "$f" || true
            ;;
        esac
        print "Removing created file: $f"
        run_cmd rm -f "$f" || true
      fi
    done < "$created"
  fi

  run_cmd systemctl daemon-reload || true
  print "Rollback finished; check logs: $LOG_FILE"
  exit 0
}

# If rollback flag given, perform rollback and exit
if [ "$ROLLBACK" -eq 1 ]; then
  rollback_changes
fi

exit 0
