#!/usr/bin/env bash
set -euo pipefail

# Verify (default) and optionally apply best settings for current public Wi‑Fi
# Usage: ./verify_public_wifi.sh [apply]

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need nmcli; need iw

active_line=$(nmcli -t -f ACTIVE,TYPE,NAME,DEVICE connection show --active 2>/dev/null | awk -F: '$1=="yes"&&$2=="wifi"{print $3"|"$4; exit}')
if [ -z "${active_line:-}" ]; then
  IF="$(iw dev 2>/dev/null | awk '/Interface/ {print $2; exit}')"
  if [ -z "${IF:-}" ]; then echo "No active Wi-Fi interface."; exit 1; fi
  SSID="$(iw dev "$IF" link 2>/dev/null | awk -F': ' '/SSID/ {print $2; exit}')"
  CN="${SSID:-unknown}"
else
  CN="${active_line%%|*}"; IF="${active_line##*|}"
fi
# CN/IF already set above

get_prop() { { nmcli -t connection show "$CN" 2>/dev/null || true; } | awk -F: -v k="$1:" '$1==k{print substr($0,length(k)+1)}'; }
SSID="$(get_prop 802-11-wireless.ssid)"
KM="$(get_prop 802-11-wireless-security.key-mgmt)"
OPEN=0; [ -z "${KM:-}" ] && OPEN=1

rt_ps=$(iw dev "$IF" get power_save 2>/dev/null | awk '{print $3}' || true)
[ -z "${rt_ps:-}" ] && rt_ps=$(iwconfig "$IF" 2>/dev/null | awk -F':|  ' '/Power Management/{print tolower($3)}' || true)
ps_conn="$(get_prop 802-11-wireless.powersave)"
cloned="$(get_prop 802-11-wireless.cloned-mac-address)"
ip6m="$(get_prop ipv6.method)"
ip6p="$(get_prop ipv6.ip6-privacy)"
mtr="$(get_prop connection.metered)"
auto="$(get_prop connection.autoconnect)"
ufw_state=$(ufw status 2>/dev/null | awk 'NR==1{print tolower($2)}') || true

ps_ok=$([ "${rt_ps}" = off ] && echo OK || echo CHANGE)
mac_ok=$([ "${cloned,,}" = random ] && echo OK || echo CHANGE)
case "${ip6m,,}" in disabled|ignore) ip6_ok=OK ;; *) ip6_ok=CHANGE ;; esac
mtr_ok=$([ "${mtr}" = no ] && echo OK || echo CHANGE)
if [ "$OPEN" -eq 1 ]; then ac_ok=$([ "${auto}" = no ] && echo OK || echo CHANGE); else ac_ok=OK; fi
fw_ok=$([ "${ufw_state}" = active ] && echo OK || echo CHANGE)
sec_label=$([ $OPEN -eq 1 ] && echo OPEN || echo SECURED)

printf "Conn:%s (%s) IF:%s Sec:%s | PowerSave:%s MAC:%s IPv6:%s Metered:%s Auto:%s FW:%s\n" \
  "${SSID:-$CN}" "$CN" "$IF" "$sec_label" "$ps_ok" "$mac_ok" "$ip6_ok" "$mtr_ok" "$ac_ok" "$fw_ok"

if [ "${1:-show}" = "apply" ]; then
  # Apply requested settings: PS off, MAC random, IPv6 disabled, Unmetered, Firewall on
  iw dev "$IF" set power_save off 2>/dev/null || sudo iw dev "$IF" set power_save off || true
  nmcli connection modify "$CN" 802-11-wireless.powersave 2 2>/dev/null || sudo nmcli connection modify "$CN" 802-11-wireless.powersave 2 || true
  nmcli connection modify "$CN" 802-11-wireless.cloned-mac-address random 2>/dev/null || sudo nmcli connection modify "$CN" 802-11-wireless.cloned-mac-address random || true
  nmcli connection modify "$CN" ipv6.method disabled 2>/dev/null || sudo nmcli connection modify "$CN" ipv6.method disabled || true
  nmcli connection modify "$CN" connection.metered no 2>/dev/null || sudo nmcli connection modify "$CN" connection.metered no || true
  sudo ufw enable >/dev/null 2>&1 || true
  if [ "$OPEN" -eq 1 ]; then
    nmcli connection modify "$CN" connection.autoconnect no 2>/dev/null || sudo nmcli connection modify "$CN" connection.autoconnect no || true
  fi
  # Re-read and print summary after applying
  rt_ps=$(iw dev "$IF" get power_save 2>/dev/null | awk '{print $3}' || true)
  [ -z "${rt_ps:-}" ] && rt_ps=$(iwconfig "$IF" 2>/dev/null | awk -F':|  ' '/Power Management/{print tolower($3)}' || true)
  cloned="$(get_prop 802-11-wireless.cloned-mac-address)"; ip6m="$(get_prop ipv6.method)"; mtr="$(get_prop connection.metered)"; auto="$(get_prop connection.autoconnect)"; ufw_state=$(ufw status 2>/dev/null | awk 'NR==1{print tolower($2)}')
  ps_ok=$([ "${rt_ps}" = off ] && echo OK || echo CHANGE)
  mac_ok=$([ "${cloned,,}" = random ] && echo OK || echo CHANGE)
  case "${ip6m,,}" in disabled|ignore) ip6_ok=OK ;; *) ip6_ok=CHANGE ;; esac
  mtr_ok=$([ "${mtr}" = no ] && echo OK || echo CHANGE)
  if [ "$OPEN" -eq 1 ]; then ac_ok=$([ "${auto}" = no ] && echo OK || echo CHANGE); else ac_ok=OK; fi
  fw_ok=$([ "${ufw_state}" = active ] && echo OK || echo CHANGE)
  printf "APPLIED -> PowerSave:%s MAC:%s IPv6:%s Metered:%s Auto:%s FW:%s\n" "$ps_ok" "$mac_ok" "$ip6_ok" "$mtr_ok" "$ac_ok" "$fw_ok"
fi
