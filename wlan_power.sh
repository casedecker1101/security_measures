 #!/usr/bin/env bash
     set -euo pipefail; IF="${1:-wlan0}"; have_sudo(){ sudo -n true >/dev/null 2>&1; }; s=( ); ip -o link show "$IF" >/dev/null 2>&1 
   || { echo "Interface $IF not found. Available:"; iw dev 2>/dev/null|awk '/Interface/{print $2}'; exit 1; }
     drv="$(ethtool -i "$IF" 2>/dev/null|awk -F': ' '/driver:/{print $2}')"; ps_b="$(iw dev "$IF" get power_save 2>/dev/null|awk 
   '{print $3}')" || true
     [ -z "${ps_b:-}" ] && ps_b="$(iwconfig "$IF" 2>/dev/null|awk -F':|  ' '/Power Management/{print tolower($3)}')" || true
     rc_b="$(cat /sys/class/net/$IF/device/power/control 2>/dev/null||true)"; tx_b="$(iwconfig "$IF" 2>/dev/null|awk -F'=|  ' 
   '/Tx-Power/{print $3}')" || true
     rfk="$(rfkill list 2>/dev/null|awk 'BEGIN{s=\"\"}/Wireless LAN/{w=1}w&&/Soft blocked/{s=$3}/Wireless LAN/{w=1}w&&/Hard 
   blocked/{h=$3}END{print s\"/\"h}')" || true
     reg="$(iw reg get 2>/dev/null|awk '/country/{print $2;exit}')" || true
     echo "BEFORE: driver=$drv ps=$ps_b rc=$rc_b tx=$tx_b rfkill(S/H)=$rfk reg=$reg"
     have_sudo || echo "Note: sudo recommended for persistence."
     sudo true 2>/dev/null || true
     iw dev "$IF" set power_save off 2>/dev/null || sudo iw dev "$IF" set power_save off || true
     [ -e "/sys/class/net/$IF/device/power/control" ] && echo on | { tee "/sys/class/net/$IF/device/power/control" >/dev/null 2>&1 ||
    sudo tee "/sys/class/net/$IF/device/power/control" >/dev/null; }
     rfkill unblock wifi 2>/dev/null || sudo rfkill unblock wifi || true
     if command -v nmcli >/dev/null 2>&1; then
       if have_sudo; then sudo mkdir -p /etc/NetworkManager/conf.d
         printf "[connection]\nwifi.powersave=2\n" | sudo tee /etc/NetworkManager/conf.d/disable-wifi-powersave.conf >/dev/null
         sudo systemctl reload NetworkManager 2>/dev/null || nmcli general reload 2>/dev/null || true
       fi
       nmcli -t -f NAME,TYPE connection show 2>/dev/null|awk -F: '$2=="wifi"{print $1}'|while read -r C; do
         nmcli connection modify "$C" 802-11-wireless.powersave 2 2>/dev/null || sudo nmcli connection modify "$C" 
   802-11-wireless.powersave 2 || true
       done
     fi
     [ "$drv" = "iwlwifi" ] && have_sudo && echo "options iwlwifi power_save=0" | sudo tee /etc/modprobe.d/iwlwifi-powersave.conf 
   >/dev/null || true
     have_sudo && echo 'ACTION=="add|change",SUBSYSTEM=="net",KERNEL=="wlan0",RUN+="/bin/sh -c '\''echo on > 
   /sys/class/net/%k/device/power/control; iw dev %k set power_save off'\''"' | sudo tee /etc/udev/rules.d/70-wlan0-fullpower.rules 
   >/dev/null && \
       sudo udevadm control --reload && sudo udevadm trigger -c add /sys/class/net/"$IF" || true
     ps_a="$(iw dev "$IF" get power_save 2>/dev/null|awk '{print $3}')" || true
     [ -z "${ps_a:-}" ] && ps_a="$(iwconfig "$IF" 2>/dev/null|awk -F':|  ' '/Power Management/{print tolower($3)}')" || true
     rc_a="$(cat /sys/class/net/$IF/device/power/control 2>/dev/null||true)"; tx_a="$(iwconfig "$IF" 2>/dev/null|awk -F'=|  ' 
   '/Tx-Power/{print $3}')" || true
     echo "AFTER:  driver=$drv ps=${ps_a:-unknown} rc=${rc_a:-n/a} tx=${tx_a:-n/a}"
     # Optional hardening: make configs immutable (undo with chattr -i)
     # sudo chattr +i /etc/NetworkManager/conf.d/disable-wifi-powersave.conf; [ -f /etc/modprobe.d/iwlwifi-powersave.conf ] && sudo 
   chattr +i /etc/modprobe.d/iwlwifi-powersave.conf; sudo chattr +i /etc/udev/rules.d/70-wlan0-fullpower.rules
