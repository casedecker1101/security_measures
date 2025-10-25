#!/usr/bin/env bash
# VSCode/dev session performance tuner (status/apply/revert/launch-code)
# Applies safe, temporary tweaks for Linux development sessions.
set -euo pipefail


# Findings: 3.6GiB RAM; 11Gi swap (swapfile pri=100); swappiness=90;
#   vfs_cache_pressure=100; inotify low; CPU governor=powersave; zswap=disabled.
#   Run: sudo ./dev_tune.sh apply && ./dev_tune.sh launch-code Review/undo anytime:
#   ./dev_tune.sh status | ./dev_tune.sh revert Optional (low-RAM boost): sudo bash
#   -lc 'modprobe zswap; echo lz4 | tee /sys/module/zswap/parameters/compressor;
#   echo 30 | tee /sys/module/zswap/parameters/max_pool_percent; echo Y | tee
#   /sys/module/zswap/parameters/enabled'



STATE_FILE=/tmp/vscode_dev_tune_state.$$ # per-run state; symlink latest kept at /tmp/vscode_dev_tune_state
LATEST_STATE_LINK=/tmp/vscode_dev_tune_state

want_swappiness=20
want_vfs_cache_pressure=50
want_inotify_watches=1048576
want_inotify_instances=4096
ulimit_n=1048576

is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }
need_sudo() { command -v sudo >/dev/null 2>&1; }

say() { printf "[dev-tune] %s\n" "$*"; }
err() { printf "[dev-tune][ERR] %s\n" "$*" >&2; }

read_sysctl() { sysctl -n "$1" 2>/dev/null || true; }
write_sysctl() {
  local key=$1 val=$2
  if is_root; then sysctl -q -w "$key=$val" >/dev/null; else sudo sysctl -q -w "$key=$val" >/dev/null; fi
}

save_kv() { echo "$1=$2" >>"${STATE_FILE}"; }
load_kv() { grep -E "^$1=" "${LATEST_STATE_LINK}" | tail -n1 | cut -d= -f2- || true; }

status() {
  echo "==== System status (read-only) ===="
  command -v lscpu >/dev/null && lscpu | sed -n '1,12p' || true
  echo
  free -h || true
  echo
  echo "Swap:" && (swapon --show || echo "(no swap active)")
  echo
  echo "Kernel params:"
  echo " vm.swappiness=$(read_sysctl vm.swappiness) (target ${want_swappiness})"
  echo " vm.vfs_cache_pressure=$(read_sysctl vm.vfs_cache_pressure) (target ${want_vfs_cache_pressure})"
  echo " fs.inotify.max_user_watches=$(read_sysctl fs.inotify.max_user_watches) (target ${want_inotify_watches})"
  echo " fs.inotify.max_user_instances=$(read_sysctl fs.inotify.max_user_instances) (target ${want_inotify_instances})"
  echo
  echo "CPU governor per core:"
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -f "$g" ]] || continue
    echo " $(basename "$(dirname "$g")"): $(cat "$g")"
  done | sort -V || true
  echo
  if [[ -r /sys/module/zswap/parameters/enabled ]]; then
    echo "zswap: enabled=$(cat /sys/module/zswap/parameters/enabled) compressor=$(cat /sys/module/zswap/parameters/compressor 2>/dev/null || echo n/a) max_pool_percent=$(cat /sys/module/zswap/parameters/max_pool_percent 2>/dev/null || echo n/a)"
  else
    echo "zswap: not available (module not loaded)"
  fi
  if compgen -G "/sys/block/zram*/disksize" >/dev/null; then
    for z in /sys/block/zram*/disksize; do echo "$(dirname "$z"): $(cat "$z")"; done
  else
    echo "zram: none"
  fi
  echo
  echo "ulimit -n (open files): $(ulimit -n) (target ${ulimit_n})"
  echo "==== End status ===="
}

apply() {
  say "Applying dev-focused settings (temporary, revertable)"
  : >"${STATE_FILE}"
  # Save current sysctl values
  for k in vm.swappiness vm.vfs_cache_pressure fs.inotify.max_user_watches fs.inotify.max_user_instances; do
    cur=$(read_sysctl "$k"); save_kv "$k" "$cur"; done
  # Apply sysctl tweaks
  write_sysctl vm.swappiness ${want_swappiness}
  write_sysctl vm.vfs_cache_pressure ${want_vfs_cache_pressure}
  write_sysctl fs.inotify.max_user_watches ${want_inotify_watches}
  write_sysctl fs.inotify.max_user_instances ${want_inotify_instances}

  # CPU governors -> performance (if supported)
  changed=0
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -w "$g" ]] || continue
    cpu=$(basename "$(dirname "$g")")
    cur=$(cat "$g")
    save_kv "gov_${cpu}" "$cur"
    if echo performance | { if is_root; then tee "$g"; else sudo tee "$g"; fi; } >/dev/null 2>&1; then changed=1; fi
  done
  save_kv governors_changed "$changed"

  # Record link to latest state
  ln -sf "${STATE_FILE}" "${LATEST_STATE_LINK}"
  say "Applied. Tip: use '$(basename "$0") launch-code' to start VSCode with high ulimit."
}

revert() {
  if [[ ! -f "${LATEST_STATE_LINK}" ]]; then err "No previous state to revert."; exit 1; fi
  say "Reverting settings from ${LATEST_STATE_LINK}"
  # Restore sysctl values
  for k in vm.swappiness vm.vfs_cache_pressure fs.inotify.max_user_watches fs.inotify.max_user_instances; do
    val=$(load_kv "$k"); [[ -n "$val" ]] && write_sysctl "$k" "$val" || true
  done
  # Restore governors
  changed=$(load_kv governors_changed)
  if [[ "$changed" == "1" ]]; then
    for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
      [[ -w "$g" ]] || continue
      cpu=$(basename "$(dirname "$g")")
      prev=$(load_kv "gov_${cpu}")
      [[ -n "$prev" ]] && echo "$prev" | { if is_root; then tee "$g"; else sudo tee "$g"; fi; } >/dev/null 2>&1 || true
    done
  fi
  say "Reverted."
}

launch_code() {
  # High file-descriptor limit only for this process tree
  ulimit -n ${ulimit_n} || true
  if command -v code >/dev/null 2>&1; then
    say "Launching VSCode (ulimit -n=${ulimit_n})"
    exec code "$@"
  else
    err "VSCode ('code') not found in PATH."; exit 1
  fi
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [status|apply|revert|launch-code [args...]]
- status       Show current settings and recommendations
- apply        Set kernel params and CPU governors for a dev session
- revert       Restore settings saved by the last apply
- launch-code  Start VSCode with elevated ulimit after manual apply
EOF
}

cmd=${1:-status}
case "$cmd" in
  status) status ;;
  apply) shift; apply ;;
  revert) shift; revert ;;
  launch-code) shift; launch_code "$@" ;;
  *) usage; exit 1 ;;
esac
