#!/usr/bin/env bash
set -euo pipefail

# Disable services that own TCP listeners with no established connections.
# Dry-run by default. Use --apply to stop+disable units. Options: --include-loopback, --include-udp

APPLY=0
INCLUDE_LOOPBACK=0
INCLUDE_UDP=0

for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --include-loopback) INCLUDE_LOOPBACK=1 ;;
    --include-udp) INCLUDE_UDP=1 ;;
    -h|--help)
      echo "Usage: $0 [--apply] [--include-loopback] [--include-udp]"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

# Require ss
command -v ss >/dev/null 2>&1 || { echo "ss not found" >&2; exit 1; }

SUDO=""
if [[ $EUID -ne 0 ]]; then SUDO="sudo"; fi

is_loopback_addr() {
  local addr="$1"
  [[ "$addr" =~ ^127\.0\.0\.1: ]] || [[ "$addr" =~ ^\[::1\]: ]] || [[ "$addr" =~ ^\[::ffff:127\.0\.0\.1\]: ]]
}

has_established_tcp_on_port() {
  local port="$1"
  # established connections where local sport equals the port
  ss -ntH state established "( sport = :$port )" | grep -q .
}

get_unit_for_pid() {
  local pid="$1"
  # Parse unit name from systemctl status <pid>
  systemctl status --no-pager "$pid" 2>/dev/null | awk 'NR==1{print $2; exit}'
}

declare -A unit_ports unit_has_est unit_is_candidate

# Collect TCP listeners
while IFS= read -r line; do
  # Extract local address:port and pid/program
  local_addr=$(awk '{print $4}' <<<"$line")
  # Skip loopback unless requested
  if [[ $INCLUDE_LOOPBACK -eq 0 ]] && is_loopback_addr "$local_addr"; then
    continue
  fi
  port="$local_addr"
  port="${port##*:}"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then continue; fi
  pid=$(sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' <<<"$line")
  if [[ -z "$pid" ]]; then
    # No owning PID found; likely a socket-activated unit (systemd). Skip.
    continue
  fi
  unit=$(get_unit_for_pid "$pid" || true)
  if [[ -z "${unit:-}" ]] || ! [[ "$unit" =~ \.service$|\.socket$ ]]; then
    # Not a systemd unit we can manage; skip
    continue
  fi
  unit_ports[$unit]="${unit_ports[$unit]:-} $port"
  if has_established_tcp_on_port "$port"; then
    unit_has_est[$unit]=1
  fi
  unit_is_candidate[$unit]=1

done < <(ss -ltnpH)

# Optionally include UDP listeners (best-effort: cannot detect established state; treat as active -> skip)
if [[ $INCLUDE_UDP -eq 1 ]]; then
  while IFS= read -r line; do
    local_addr=$(awk '{print $5}' <<<"$line")
    if [[ $INCLUDE_LOOPBACK -eq 0 ]] && is_loopback_addr "$local_addr"; then continue; fi
    pid=$(sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' <<<"$line")
    if [[ -z "$pid" ]]; then
      continue
    fi
    unit=$(get_unit_for_pid "$pid" || true)
    if [[ -z "${unit:-}" ]] || ! [[ "$unit" =~ \.service$|\.socket$ ]]; then continue; fi
    unit_ports[$unit]="${unit_ports[$unit]:-} udp"
    unit_has_est[$unit]=1  # treat UDP as active to avoid false positives
    unit_is_candidate[$unit]=1
  done < <(ss -lnupH)
fi

shopt -s nullglob

candidates=()
for unit in "${!unit_is_candidate[@]}"; do
  if [[ -z "${unit_has_est[$unit]:-}" ]]; then
    candidates+=("$unit")
  fi
done

if [[ ${#candidates[@]} -eq 0 ]]; then
  echo "No idle units found to disable."
  exit 0
fi

if [[ $APPLY -eq 0 ]]; then
  echo "Dry run. Units that would be disabled (no established TCP connections):"
  for u in "${candidates[@]}"; do
    echo "  $u (ports:${unit_ports[$u]})"
  done
  echo "Run with --apply to stop and disable them."
  exit 0
fi

for u in "${candidates[@]}"; do
  echo "Disabling $u (ports:${unit_ports[$u]})"
  $SUDO systemctl disable --now "$u" || echo "Failed to disable $u" >&2
done

echo "Done."