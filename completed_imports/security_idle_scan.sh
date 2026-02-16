#!/usr/bin/env bash
# security_idle_scan.sh - Lightweight periodic network + host IOC scan when system idle
# Requirements: bash, ss, ps, awk, grep, stat, systemd-run (for timer usage); optional: tshark, rkhunter, chkrootkit
# Output: summary + artifacts under /var/log/security_idle_scan/
set -euo pipefail

LOG_DIR=/var/log/security_idle_scan
mkdir -p "$LOG_DIR"
TS=$(date +%Y%m%d_%H%M%S)
PCAP="$LOG_DIR/capture_${TS}.pcap"
SUMMARY="$LOG_DIR/summary_${TS}.txt"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

#--------------- Idle Checks ----------------
# Consider idle if:  loadavg(1m) < 0.5 * cores  AND no active non-root TTY except maybe our automation
cores=$(getconf _NPROCESSORS_ONLN || echo 1)
load1=$(awk '{print $1}' /proc/loadavg)
# bc may not exist – compare via awk numeric
idle_load=$(awk -v l="$load1" -v c="$cores" 'BEGIN{if(l < (0.5*c)) print 1; else print 0}')
active_users=$(who | awk '{print $1}' | sort -u | wc -l || true)
if [[ ${idle_load} -ne 1 || ${active_users} -gt 0 ]]; then
  echo "[INFO] Not idle (load=$load1 cores=$cores users=$active_users); exiting." | tee -a "$LOG_DIR/last_run.log"
  exit 0
fi

#--------------- Network Capture (if tshark) --------------
CAP_SECONDS=${CAP_SECONDS:-600} # 10 minutes
if command -v tshark >/dev/null 2>&1; then
  echo "[INFO] Capturing network traffic for ${CAP_SECONDS}s" | tee -a "$SUMMARY"
  # Ring buffer to avoid huge files
  tshark -q -a duration:$CAP_SECONDS -b filesize:25 -b files:2 -w "$PCAP" 2>>"$SUMMARY" || echo "[WARN] tshark capture issue" >>"$SUMMARY"
else
  echo "[WARN] tshark not installed; skipping packet capture" | tee -a "$SUMMARY"
  PCAP="" # Mark absent
fi

#--------------- Host Enumeration ----------------
{
  echo "== TIME =="; date -u
  echo "== KERNEL =="; uname -a
  echo "== UPTIME =="; uptime
  echo "== LOAD =="; cat /proc/loadavg

  echo "\n== LISTENING SOCKETS (uncommon) =="
  ss -tulpn 2>/dev/null | grep -vE ':(22|80|443|53|123|25|587|110|143|993|995|3306|5432) ' || true

  echo "\n== ESTABLISHED EXTERNAL CONNECTIONS =="
  ss -tunp 2>/dev/null | awk 'NR==1||/ESTAB/' | grep -v 127.0.0.1 || true

  echo "\n== SUSPICIOUS PROCESSES (netcat/socat/reverse shells) =="
  ps -eo pid,ppid,user,cmd --sort=cmd | grep -E 'nc |ncat|socat|/dev/tcp|bash -i|python3 -c|perl -e|php -r|ruby -e|ssh -R|ssh -L' || echo "None"

  echo "\n== WORLD-WRITABLE EXECUTABLES (potential trojans) =="
  find /usr/local/bin /usr/bin /bin 2>/dev/null -maxdepth 1 -type f -perm -0002 -exec ls -l {} + || true

  echo "\n== CRON JOBS (search for curl|wget|base64|sh -c) =="
  for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/CRON($u): /"; done | grep -Ei 'curl|wget|base64|bash|sh -c' || echo "No suspicious cron entries"

  echo "\n== SYSTEMD UNITS (curl|wget piping) =="
  grep -RIlE 'curl .*\||wget .*\|' /etc/systemd/system /lib/systemd/system 2>/dev/null | sed 's/^/UNIT_MATCH: /' || echo "No suspicious unit ExecStart matches"

  echo "\n== RECENTLY MODIFIED BINARIES (48h) =="
  find /usr/local/bin /usr/bin /bin -type f -mtime -2 -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | head -n 50

  echo "\n== AUTH LOG (last 50 failed) =="
  journalctl -q -u ssh --since "48 hours ago" 2>/dev/null | grep -i 'fail\|invalid' | tail -n 50 || true
} >>"$SUMMARY"

#--------------- PCAP Analysis ----------------
if [[ -n "$PCAP" && -f "$PCAP" ]]; then
  {
    echo "\n== PCAP ANALYSIS ($PCAP) =="
    echo "-- New TCP SYN (outbound) --"
    tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport 2>/dev/null \
      | awk '{printf "%s src=%s:%s -> %s:%s\n", strftime("%Y-%m-%dT%H:%M:%SZ", $1), $2,$3,$4,$5}' | head -n 50

    echo "-- DNS Queries with long or high-digit labels --"
    tshark -r "$PCAP" -Y "dns.qry.name" -T fields -e dns.qry.name 2>/dev/null \
      | awk -F'.' '{for(i=1;i<=NF;i++){d=gsub(/[0-9]/,"",$i); if(length($i)>25 || d<length($i)/2){print $0;break}}}' | sort -u | head -n 50

    echo "-- Suspicious Ports Contacted (4444,8081,1337,9001) --"
    tshark -r "$PCAP" -Y "tcp.dstport in {4444 8081 1337 9001}" -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport 2>/dev/null | head -n 50

    echo "-- Potential Periodic Beacons (small TCP packets) --"
    tshark -r "$PCAP" -Y "tcp.len==0" -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport 2>/dev/null \
      | awk '{k=$2":"$3; c[k]++;} END{for(i in c) if(c[i]>20) print i, c[i]}' | sort -k2 -nr | head -n 20
  } >>"$SUMMARY"
fi

#--------------- Optional Rootkit Scans ----------------
if command -v rkhunter >/dev/null 2>&1; then
  echo "\n== RKHUNTER (summary) ==" >>"$SUMMARY"
  rkhunter --check --sk | grep -E 'Warning|[0-9]+ vulnerabilities' >>"$SUMMARY" 2>/dev/null || true
fi
if command -v chkrootkit >/dev/null 2>&1; then
  echo "\n== CHKROOTKIT ==" >>"$SUMMARY"
  chkrootkit 2>/dev/null | grep -Ev 'not infected' >>"$SUMMARY" || true
fi

#--------------- Final Heuristic Summary ---------------
SCORE=0
syn_count=$(grep -c 'src=' "$SUMMARY" || echo 0)
(( syn_count > 200 )) && SCORE=$((SCORE+1))
beacon_lines=$(grep -c 'Potential Periodic Beacons' -A5 "$SUMMARY" | tail -n +2 | wc -l)
(( beacon_lines > 5 )) && SCORE=$((SCORE+1))
cron_susp=$(grep -c 'CRON(' "$SUMMARY" || echo 0)
(( cron_susp > 0 )) && SCORE=$((SCORE+1))
open_uncommon=$(grep -c LISTEN "$SUMMARY" || echo 0)
(( open_uncommon > 30 )) && SCORE=$((SCORE+1))

{
  echo "\n== RISK SCORE == $SCORE (0=clean, >=2=review)"
  echo "Artifacts: SUMMARY=$SUMMARY PCAP=${PCAP:-none}"
} >>"$SUMMARY"

ln -sf "$SUMMARY" "$LOG_DIR/last_summary.txt"
chmod 600 "$SUMMARY" "$PCAP" 2>/dev/null || true

echo "[DONE] Security idle scan complete: $SUMMARY"
