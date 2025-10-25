# ...existing code...
#!/usr/bin/env bash
# Prepare nftables+fail2ban config, restart services, collect .deb files for offline install and package everything.
set -euo pipefail

SRC_JAILS="/home/burnone/flatdixiemkI/archive/completed_imports/fail2ban_100_jails.local"
DST_JAILS="/etc/fail2ban/jails.local"
NFT_ACTION="/etc/fail2ban/action.d/nftables.conf"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
OUTDIR="/home/burnone/flatdixiemkI/offline_package_${TIMESTAMP}"
DEB_DIR="${OUTDIR}/debs"
PKGS="fail2ban nftables"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash $0"
  exit 1
fi

mkdir -p "${OUTDIR}" "${DEB_DIR}"

echo "1) Backing up existing configs..."
[ -f "${NFT_ACTION}" ] && cp -av "${NFT_ACTION}" "${NFT_ACTION}.bak.${TIMESTAMP}"
[ -f "${DST_JAILS}" ] && cp -av "${DST_JAILS}" "${DST_JAILS}.bak.${TIMESTAMP}"

echo "2) Patch nftables action to allow prefix elements (flags interval)..."
if [ -f "${NFT_ACTION}" ]; then
  # safe perl inplace replace; create temp backup too
  perl -0777 -pe '
    BEGIN { $saw=0; }
    if (s{add set <table_family> <table> <addr_set> \{ type <addr_type>\; \}}{add set <table_family> <table> <addr_set> \{ type <addr_type>\; flags interval\; \}}gs) { $saw=1 }
    END { print "" }
  ' -i.bak "${NFT_ACTION}"
  echo "Patched ${NFT_ACTION} (backup ${NFT_ACTION}.bak)"
else
  echo "Warning: ${NFT_ACTION} not present; skipping patch."
fi

echo "3) Deploy 100-jail config..."
if [ -f "${SRC_JAILS}" ]; then
  cp -av "${SRC_JAILS}" "${DST_JAILS}"
  chmod 644 "${DST_JAILS}"
else
  echo "Source jails file not found: ${SRC_JAILS}"
  exit 2
fi

echo "4) Download .deb packages for offline install (apt cache will be used)."
# Update apt metadata
apt-get update -y

# Use --download-only to populate /var/cache/apt/archives
apt-get install --download-only -y ${PKGS}

# copy downloaded debs (current cache) to package dir
cp -av /var/cache/apt/archives/*.deb "${DEB_DIR}/" || true

# Also include currently cached dependency candidates via apt-get download of listed packages
# Collect additional candidate URIs via apt-get --print-uris if necessary (best-effort)
for p in ${PKGS}; do
  # apt-get download will download package file for the candidate version
  apt-get download "${p}" 2>/dev/null || true
done

# move any downloaded debs in cwd to the package dir
mv -v ./*.deb "${DEB_DIR}/" 2>/dev/null || true

echo "5) Copy installer script and config to package..."
# copy this script and the jails file and nft action (if patched) into the archive
cp -av "$0" "${OUTDIR}/"
cp -av "${DST_JAILS}" "${OUTDIR}/"
[ -f "${NFT_ACTION}" ] && cp -av "${NFT_ACTION}" "${OUTDIR}/"

echo "6) Create tarball for offline transfer..."
TARBALL="${OUTDIR}.tar.gz"
tar -C "$(dirname "${OUTDIR}")" -czvf "${TARBALL}" "$(basename "${OUTDIR}")"

echo "7) Restart nftables and fail2ban and run quick checks..."
systemctl restart nftables || echo "nftables restart warning"
if ! systemctl restart fail2ban; then
  echo "fail2ban restart failed; show journal tail:"
  journalctl -u fail2ban -n 200 --no-pager
fi

sleep 2
echo
echo "fail2ban status:"
fail2ban-client status || true
echo
echo "nftables summary (showing chains):"
nft list ruleset | sed -n '1,120p' || true

echo
echo "Recent fail2ban errors (grep):"
tail -n 200 /var/log/fail2ban.log | rg -n 'ERROR|nft|nftables|f2b' || true

echo
echo "Offline package created at: ${TARBALL}"
echo "To install on an offline host:"
cat <<'EOF'
1) Copy the tarball to offline host and extract:
   tar xzf offline_package_...tar.gz -C /tmp
2) Install .deb files:
   sudo dpkg -i /tmp/offline_package_.../debs/*.deb || sudo apt-get -f install
3) Copy configs and installer script and run the installer as root:
   sudo cp /tmp/offline_package_.../jails.local /etc/fail2ban/jails.local
   sudo cp /tmp/offline_package_.../nftables.conf /etc/fail2ban/action.d/nftables.conf   # if present
   sudo bash /tmp/offline_package_.../setup_nft_fail2ban_offline_package.sh   # to restart services
EOF

echo "Done."
# ...existing code...