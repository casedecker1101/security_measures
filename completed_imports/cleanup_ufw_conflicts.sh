#!/usr/bin/env bash
set -euo pipefail

# Re-exec as root if needed
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exec sudo -n bash "$0" "$@" || exec sudo bash "$0" "$@"
fi

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi

# Tokens to match conflicting DENY rules (spec field in `ufw status numbered`)
read -r -d '' RAW_LIST <<'EOF'
DNS,Apache,LDAP,OpenSSH,192.0.0.0/24/tcp,142.0.0.0/24/tcp,10.15.225.107/tcp,10.15.0.0/24/tcp,169.0.0.0/24/tcp,200.0.0.0/24/tcp,162.159.0.0/24/tcp,151.101.0.0/24/tcp,172.0.0.0/24/tcp,13.0.0.0/24/tcp,22/tcp,67/udp,53,192.168.173.178/tcp,192.168.109.99/tcp,192.168.173.178/udp,192.168.109.99/udp,127.0.0.54/udp,127.0.0.53/udp,192.168.139.150/udp,192.168.139.150/tcp,22
EOF

# Numbers explicitly listed to delete (will be intersected with current rules)
NUM_LIST=(1 2 3 4 5 6 7 8 9)

# Normalize RAW_LIST into array of specs (trim spaces, drop empties)
mapfile -t SPEC_LIST < <(echo "$RAW_LIST" | tr ',' '\n' | sed -E 's/^\s+|\s+$//g' | awk 'NF>0' | sort -u)

# Fetch current UFW rules (numbered)
STATUS=$(ufw status numbered 2>/dev/null || true)

if [[ -z $STATUS ]]; then
  echo "No UFW rules found or ufw disabled." >&2
  exit 0
fi

echo "$STATUS" | sed -n '1,200p'

# Build deletion list: any rule with number in NUM_LIST, or action DENY and spec matches SPEC_LIST token (case-insensitive)
# Output format: num\treason\toriginal_line
DEL_CAND=$(echo "$STATUS" | awk -v IGNORECASE=1 -v specs="$(printf '%s|' "${SPEC_LIST[@]}" | sed 's/|$//')" '
  match($0, /^\[[[:space:]]*([0-9]+)\][[:space:]]+(.+)[[:space:]]+(ALLOW|DENY)[[:space:]]+(IN|OUT)[[:space:]]+/, m) {
    num=m[1]; spec=m[2]; act=m[3]; dir=m[4];
    gsub(/[[:space:]]+$/, "", spec);
    if (act == "DENY" && spec ~ "(^|[[:space:]])(" specs ")($|[[:space:]])") {
      print num "\tSPEC:" spec "\t" $0;
    }
  }
')

# Also mark explicit numbers
for n in "${NUM_LIST[@]}"; do
  line=$(echo "$STATUS" | awk -v n="$n" 'match($0, /^\[[[:space:]]*([0-9]+)\]/, m){ if (m[1]==n){print $0; exit}}') || true
  [[ -n "$line" ]] && DEL_CAND+=$'\n'"$n	NUM:$n	$line"
done

# Collect unique numbers to delete
mapfile -t NUMS < <(echo "$DEL_CAND" | awk -F '\t' 'NF{print $1}' | sort -u -nr)

if [[ ${#NUMS[@]} -eq 0 ]]; then
  echo "No matching conflicting DENY rules found to delete."
  exit 0
fi

echo "Planned deletions (in descending order):" >&2
for n in "${NUMS[@]}"; do
  echo "$DEL_CAND" | awk -F '\t' -v n="$n" '$1==n{print $0}' | head -n1
done | sed 's/^/[delete] /'

# Delete rules by number in descending order to keep numbering stable
for n in "${NUMS[@]}"; do
  echo "Deleting rule #$n" >&2
  yes | ufw delete "$n" >/dev/null || true
  # Refresh numbering after each delete
  STATUS=$(ufw status numbered 2>/dev/null || true)
  # Recompute remaining numbers mapping after deletion
  # Skip recomputing list; we delete strictly descending initial snapshot to avoid renumber conflicts
done

echo "Remaining UFW rules:"
ufw status numbered || true
