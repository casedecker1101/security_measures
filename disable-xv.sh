#!/usr/bin/env bash
# disable-xv.sh
# Creates an Xorg config to disable the XVideo (Xv) extension and disables the Xv module.
# Usage: sudo ./disable-xv.sh [--dry-run]

set -euo pipefail

DRY_RUN=0
FORCE=0
VERIFY_ONLY=0
APPLY_AND_VERIFY=1
RESTART_DM=0
APPLY_FIREWALL=1
DISABLE_SSH_X11=1
REVERT_FIREWALL=0
if [ "${1:-}" = "--dry-run" ] || [ "${2:-}" = "--dry-run" ]; then
  DRY_RUN=1
fi
if [ "${1:-}" = "--force" ] || [ "${2:-}" = "--force" ]; then
  FORCE=1
fi
if [ "${1:-}" = "--verify-only" ] || [ "${2:-}" = "--verify-only" ]; then
  VERIFY_ONLY=1
fi
if [ "${1:-}" = "--apply-and-verify" ] || [ "${2:-}" = "--apply-and-verify" ]; then
  APPLY_AND_VERIFY=1
fi
if [ "${1:-}" = "--restart-dm" ] || [ "${2:-}" = "--restart-dm" ]; then
  RESTART_DM=1
fi
if [ "${1:-}" = "--apply-firewall" ] || [ "${2:-}" = "--apply-firewall" ]; then
  APPLY_FIREWALL=1
fi
if [ "${1:-}" = "--disable-ssh-x11" ] || [ "${2:-}" = "--disable-ssh-x11" ]; then
  DISABLE_SSH_X11=1
fi
if [ "${1:-}" = "--revert-firewall" ] || [ "${2:-}" = "--revert-firewall" ]; then
  REVERT_FIREWALL=1
fi

CONF_DIR="/etc/X11/xorg.conf.d"
CONF_FILE="99-disable-xv.conf"
TARGET="${CONF_DIR}/${CONF_FILE}"

CONF_CONTENT=$(cat <<'EOF'
# Disable XVideo/Xv extension and module to stop Wayland/XWayland Xv bridging
Section "Extensions"
    Option "XVideo" "Disable"
EndSection

Section "Module"
    # prevent the Xv module from loading if present
    Disable "xv"
EndSection

# Also disable remote access (no TCP listening / no XDMCP)
Section "ServerFlags"
  # prevent the X server from listening on TCP for remote X clients
  Option "DontListen" "TCP"
  # disable XDMCP (X Display Manager Control Protocol)
  Option "DontVTSwitch" "false"
  Option "AllowEmptyInput" "false"
EndSection
EOF
)

if [ $DRY_RUN -eq 1 ]; then
  echo "DRY RUN: would write to ${TARGET}:"
  echo
  echo "$CONF_CONTENT"
  exit 0
fi

if [ $VERIFY_ONLY -eq 1 ]; then
  # Verify config presence
  echo "Verification-only mode: checking system lock-down..."
  ok=0
  if [ -f "$TARGET" ]; then
    echo "Found ${TARGET}"
    # Check owner and permissions
    owner=$(stat -c '%U:%G' "$TARGET" 2>/dev/null || true)
    perms=$(stat -c '%a' "$TARGET" 2>/dev/null || true)
    echo "Ownership: ${owner:-unknown}, Permissions: ${perms:-unknown}"
    if [ "${owner:-}" != "root:root" ]; then
      echo "WARNING: ${TARGET} should be owned by root:root" >&2
    else
      ok=$((ok+1))
    fi
    if [ "${perms:-}" != "644" ] && [ "${perms:-}" != "0644" ]; then
      echo "WARNING: ${TARGET} should have permissions 644" >&2
    else
      ok=$((ok+1))
    fi

    # Content checks
    if grep -q "Section \"ServerFlags\"" "$TARGET" >/dev/null 2>&1 && grep -q "Option \"DontListen\" \"TCP\"" "$TARGET" >/dev/null 2>&1; then
      echo "ServerFlags and DontListen TCP present"
      ok=$((ok+1))
    else
      echo "WARNING: ServerFlags/DontListen TCP not present in ${TARGET}" >&2
    fi
    if grep -q "Option \"XVideo\" \"Disable\"" "$TARGET" >/dev/null 2>&1 && grep -q "Section \"Module\"" "$TARGET" >/dev/null 2>&1; then
      echo "XVideo disable and Module disable present"
      ok=$((ok+1))
    else
      echo "WARNING: XVideo/Module disable not fully present in ${TARGET}" >&2
    fi
  else
    echo "Configuration file ${TARGET} not found." >&2
  fi

  # Check for TCP listeners on X11 port 6000 (advanced: across netns if ip netns present)
  if command -v ss >/dev/null 2>&1; then
    found=1
    # if ip netns is available, scan each network namespace
    if command -v ip >/dev/null 2>&1 && ip netns list >/dev/null 2>&1; then
      for ns in $(ip netns list | awk '{print $1}'); do
        if ip netns exec "$ns" ss -tln | grep -q ':6000\>'; then
          echo "WARNING: TCP port 6000 is listening in netns $ns - remote X may be possible" >&2
          found=0
        fi
      done
    fi
    if ss -tln | grep -q ':6000\>'; then
      echo "WARNING: TCP port 6000 is listening - remote X may be possible" >&2
      found=0
    fi
    if [ "$found" -ne 0 ]; then
      echo "No TCP listeners on port 6000"
      ok=$((ok+1))
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -tln | grep -q ':6000\>'; then
      echo "WARNING: TCP port 6000 is listening - remote X may be possible" >&2
    else
      echo "No TCP listeners on port 6000"
      ok=$((ok+1))
    fi
  else
    echo "Note: cannot check port 6000 listeners (ss/netstat not found)" >&2
  fi

  # Additional display manager XDMCP checks
  dm_ok=0
  # GDM
  if [ -f /etc/gdm/custom.conf ]; then
    if grep -Eq "(?i)\bEnable\b\s*=\s*1" /etc/gdm/custom.conf; then
      echo "WARNING: GDM XDMCP may be enabled in /etc/gdm/custom.conf" >&2
    else
      echo "GDM XDMCP not enabled or not set to 1"
      dm_ok=$((dm_ok+1))
    fi
  fi
  # LightDM
  if ls /etc/lightdm/lightdm.conf* >/dev/null 2>&1; then
    if grep -Riq "xdmcp" /etc/lightdm 2>/dev/null; then
      echo "WARNING: LightDM XDMCP-related settings found under /etc/lightdm" >&2
    else
      echo "No LightDM XDMCP settings found under /etc/lightdm"
      dm_ok=$((dm_ok+1))
    fi
  fi
  # SDDM
  if [ -f /etc/sddm.conf ]; then
    if grep -Eiq "(?i)xdmcp|DisplayServer" /etc/sddm.conf; then
      echo "WARNING: SDDM may be configured to use XDMCP in /etc/sddm.conf" >&2
    else
      echo "No SDDM XDMCP settings found"
      dm_ok=$((dm_ok+1))
    fi
  fi
  # KDM (legacy)
  if [ -f /etc/kde4/kdm/kdmrc ] || [ -f /etc/kde/kdm/kdmrc ]; then
    kdmfile=""
    if [ -f /etc/kde4/kdm/kdmrc ]; then kdmfile=/etc/kde4/kdm/kdmrc; fi
    if [ -f /etc/kde/kdm/kdmrc ]; then kdmfile=/etc/kde/kdm/kdmrc; fi
    if [ -n "$kdmfile" ]; then
      if grep -Eiq "(?i)\bEnable\b.*XDMCP|XDMCP\b" "$kdmfile"; then
        echo "WARNING: KDM may be configured for XDMCP in ${kdmfile}" >&2
      else
        echo "No KDM XDMCP settings found in ${kdmfile}"
        dm_ok=$((dm_ok+1))
      fi
    fi
  fi
  if [ "$dm_ok" -gt 0 ]; then
    ok=$((ok+1))
  fi

  # Check for VNC services
  vnc_ok=0
  for svc in vino-server x11vnc vncserver vnc4server tigervnc tightvnc xvnc realvnc-vnc-server; do
    if pgrep -f "$svc" >/dev/null 2>&1 || systemctl list-units --type=service --all | grep -q "$svc"; then
      echo "WARNING: VNC service or process detected: $svc" >&2
    else
      vnc_ok=$((vnc_ok+1))
    fi
  done
  if [ $vnc_ok -ge 4 ]; then
    ok=$((ok+1))
  fi

  # Check SSH X11 forwarding setting (prefer runtime sshd -T if available)
  ssh_x11_ok=0
  if command -v sshd >/dev/null 2>&1; then
    if sshd -T 2>/dev/null | awk '/^x11forwarding /{print $2}' | grep -Eq "^yes$"; then
      echo "WARNING: SSH X11Forwarding enabled (runtime setting)" >&2
    else
      echo "SSH X11Forwarding disabled (runtime)"
      ssh_x11_ok=1
    fi
  elif [ -f /etc/ssh/sshd_config ]; then
    if grep -Eiq "^\s*X11Forwarding\s+yes\b" /etc/ssh/sshd_config; then
      echo "WARNING: SSH X11Forwarding enabled in /etc/ssh/sshd_config" >&2
    else
      echo "SSH X11Forwarding not enabled (or explicitly disabled)"
      ssh_x11_ok=1
    fi
  else
    echo "SSH server config not found; skipping SSH X11 forwarding check"
  fi
  if [ $ssh_x11_ok -eq 1 ]; then
    ok=$((ok+1))
  fi

  if [ $ok -ge 4 ]; then
    echo "Verification passed: system appears locked down from remote X viewing"
    exit 0
  else
  echo "Verification failed: see warnings above" >&2
    # Print summary as machine-readable: comma-separated failed checks
    summary=""
    # build summary for common checks
    if [ ! -f "$TARGET" ]; then
      summary+="missing_config,"
      mask=$((mask | 1))
    fi
    if ss -tln 2>/dev/null | grep -q ':6000\>'; then
      summary+="port6000_open,"
      mask=$((mask | 2))
    fi
    # DM XDMCP warnings
    if grep -Eq "(?i)\bEnable\b\s*=\s*1" /etc/gdm/custom.conf 2>/dev/null; then
      summary+="gdm_xdmcp,"
      mask=$((mask | 4))
    fi
    if grep -Riq "xdmcp" /etc/lightdm 2>/dev/null; then
      summary+="lightdm_xdmcp,"
      mask=$((mask | 8))
    fi
    if grep -Eiq "(?i)xdmcp|DisplayServer" /etc/sddm.conf 2>/dev/null; then
      summary+="sddm_xdmcp,"
      mask=$((mask | 16))
    fi
    # Include VNC checks
    vnc_any=0
    for svc in vino-server x11vnc vncserver vnc4server tigervnc tightvnc xvnc realvnc-vnc-server; do
      if pgrep -f "$svc" >/dev/null 2>&1 || systemctl list-units --type=service --all | grep -q "$svc"; then
        summary+="vnc:$svc,"
        vnc_any=1
      fi
    done
    if [ $vnc_any -eq 1 ]; then
      mask=$((mask | 32))
    fi
    # SSH X11
    if (command -v sshd >/dev/null 2>&1 && sshd -T 2>/dev/null | awk '/^x11forwarding /{print $2}' | grep -Eq "^yes$") || grep -Eiq "^\s*X11Forwarding\s+yes\b" /etc/ssh/sshd_config 2>/dev/null; then
      summary+="ssh_x11_forwarding,"
      mask=$((mask | 64))
    fi
    if [ -n "$summary" ]; then
      # remove trailing comma
      summary=${summary%,}
      echo "SUMMARY:${summary}" >&2
    fi
    # Use bitmask as exit code (cap to 255)
    if [ $mask -eq 0 ]; then
      exit 2
    else
      exit $((mask & 255))
    fi
  fi
fi

if [ $APPLY_AND_VERIFY -eq 1 ]; then
  # Apply the configuration then re-run verification
  echo "Applying configuration and verifying..."
  if [ "$EUID" -ne 0 ]; then
    echo "This operation requires root. Run with sudo." >&2
    exit 1
  fi
  # Write config
  mkdir -p "$CONF_DIR"
  if [ -f "$TARGET" ]; then
    cp -a "$TARGET" "${TARGET}.bak.$(date +%s)"
    echo "Backed up existing ${TARGET}"
  fi
  cat > "$TARGET" <<EOF
$CONF_CONTENT
EOF
  chown root:root "$TARGET"
  chmod 644 "$TARGET"
  echo "Config written to ${TARGET}"

  if [ $RESTART_DM -eq 1 ]; then
    # Try restart common DMs in order of common usage
    echo "Restarting display manager(s) to apply config..."
    for svc in gdm sddm lightdm lxdm xdm; do
      if systemctl list-units --type=service --all | grep -q "^${svc}.service"; then
        echo "Restarting ${svc}.service"
        systemctl restart ${svc}.service || echo "Failed to restart ${svc}.service" >&2
      fi
    done
  fi

  # Firewall remediation: block TCP 6000
  if [ $APPLY_FIREWALL -eq 1 ]; then
    echo "Applying firewall rule to block TCP port 6000 (X11)..."
    if command -v ufw >/dev/null 2>&1; then
      ufw deny 6000/tcp || echo "Failed to add ufw rule" >&2
      ufw reload || true
      # record action
      mkdir -p /var/lib/disable-xv
      echo "ufw" > /var/lib/disable-xv/firewall.method
      echo "6000/tcp" >> /var/lib/disable-xv/firewall.rules
    elif command -v nft >/dev/null 2>&1; then
      # try to add a basic nft rule in the inet filter input chain
      nft add rule inet filter input tcp dport 6000 drop 2>/dev/null || echo "Failed to add nft rule (needs manual persistence)" >&2
      mkdir -p /var/lib/disable-xv
      echo "nft" > /var/lib/disable-xv/firewall.method
      echo "inet filter input tcp dport 6000 drop" >> /var/lib/disable-xv/firewall.rules
      # Try to persist nft rules by saving to /etc/nftables.conf if available
      if [ -f /etc/nftables.conf ]; then
        if ! grep -q "tcp dport 6000 drop" /etc/nftables.conf; then
          cp -a /etc/nftables.conf /etc/nftables.conf.disable-xv.bak.$(date +%s)
          echo "add rule inet filter input tcp dport 6000 drop" >> /etc/nftables.conf
          echo "(added rule to /etc/nftables.conf for persistence)"
        fi
      fi
    elif command -v iptables >/dev/null 2>&1; then
      iptables -I INPUT -p tcp --dport 6000 -j DROP || echo "Failed to add iptables rule" >&2
      mkdir -p /var/lib/disable-xv
      echo "iptables" > /var/lib/disable-xv/firewall.method
      echo "-I INPUT -p tcp --dport 6000 -j DROP" >> /var/lib/disable-xv/firewall.rules
      # Try to save iptables rules using iptables-persistent if present
      if dpkg -l iptables-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4
      fi
    else
      echo "No supported firewall tool found (ufw/nft/iptables). Please add a rule to block TCP 6000 manually." >&2
    fi
  fi

  # SSH X11 remediation
  if [ $DISABLE_SSH_X11 -eq 1 ]; then
    echo "Disabling SSH X11 forwarding in /etc/ssh/sshd_config..."
    if [ -f /etc/ssh/sshd_config ]; then
      # backup
      cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.disable-xv.bak.$(date +%s)
      # comment out any X11Forwarding yes and set X11Forwarding no
      sed -i 's/^\s*X11Forwarding\s\+yes/# &/I' /etc/ssh/sshd_config || true
      if grep -Eiq "^\s*X11Forwarding\s+no\b" /etc/ssh/sshd_config; then
        echo "X11Forwarding already set to no"
      else
        echo "X11Forwarding no" >> /etc/ssh/sshd_config
      fi
      systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || echo "Reload sshd failed; please restart SSH service manually" >&2
    else
      echo "/etc/ssh/sshd_config not found; cannot disable SSH X11 forwarding" >&2
    fi

    # Re-run verification
    exec "$0" --verify-only
  fi

  if [ $REVERT_FIREWALL -eq 1 ]; then
    echo "Reverting firewall rules added by disable-xv..."
    if [ -f /var/lib/disable-xv/firewall.method ]; then
      method=$(cat /var/lib/disable-xv/firewall.method)
      if [ "$method" = "ufw" ]; then
        ufw delete deny 6000/tcp || echo "Failed to remove ufw rule" >&2
        ufw reload || true
      elif [ "$method" = "nft" ]; then
        # Best effort: remove matching rule(s)
        if command -v nft >/dev/null 2>&1; then
          # Attempt to flush matching rule by deleting any with that commentless match
          nft delete rule inet filter input tcp dport 6000 drop 2>/dev/null || echo "Failed to remove nft rule; please remove manually" >&2
        fi
        # If we edited /etc/nftables.conf, attempt to remove the corresponding line
        if [ -f /etc/nftables.conf.disable-xv.bak.* ]; then
          # leave backups; do not auto-edit complex configs
          true
        fi
      elif [ "$method" = "iptables" ]; then
        iptables -D INPUT -p tcp --dport 6000 -j DROP 2>/dev/null || echo "Failed to remove iptables rule; please remove manually" >&2
        if dpkg -l iptables-persistent >/dev/null 2>&1; then
          netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4
        fi
      fi
      rm -f /var/lib/disable-xv/firewall.method /var/lib/disable-xv/firewall.rules
    else
      echo "No firewall data found at /var/lib/disable-xv; cannot automatically revert" >&2
    fi
    exit 0
  fi

  # Re-run verification
  exec "$0" --verify-only
fi

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root to write to ${CONF_DIR}. Use sudo." >&2
  exit 1
fi

mkdir -p "$CONF_DIR"

# Detect if X11/XWayland is present
detected=""
if command -v Xorg >/dev/null 2>&1 || command -v X >/dev/null 2>&1; then
  detected="Xorg binary found"
fi
if pgrep -x Xorg >/dev/null 2>&1 || pgrep -f Xwayland >/dev/null 2>&1 || pgrep -x X >/dev/null 2>&1; then
  detected="X server process detected (Xorg/Xwayland)"
fi

if [ -z "$detected" ] && [ $FORCE -ne 1 ]; then
  echo "Warning: No X server (Xorg/Xwayland) detected on this system." >&2
  echo "This script will still write the config, but it may not be necessary or have any effect." >&2
  echo "If you are sure you want to proceed, re-run with --force." >&2
  echo "Use --dry-run to preview the config without writing." >&2
  exit 1
else
  echo "$detected"
fi

# Backup if existing
if [ -f "$TARGET" ]; then
  cp -a "$TARGET" "${TARGET}.bak.$(date +%s)"
  echo "Backed up existing ${TARGET} to ${TARGET}.bak.*"
fi

cat > "$TARGET" <<EOF
$CONF_CONTENT
EOF

chmod 644 "$TARGET"

# Inform user
cat <<MSG
Wrote ${TARGET} to disable Xv.
To apply, restart your X/Wayland session (logout/login) or reboot.
Note: XWayland runs as an X server process under Wayland; disabling the Xv extension in Xorg will prevent X clients using Xv from using the Xv extension when served by XWayland.
MSG

exit 0
