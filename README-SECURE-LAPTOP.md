Secure laptop setup script
=========================

What this is
------------

An idempotent shell script to apply common local laptop hardening steps using:

- UFW (Uncomplicated Firewall)
- Fail2Ban
- nftables (optional; intended as a replacement for UFW when used)

Files
-----

- `scripts/secure_laptop.sh` — the main script. Run as root (sudo).

Quick usage
-----------

Run interactively (recommended):

```bash
sudo ./scripts/secure_laptop.sh
```

Dry-run (prints actions without making changes):

```bash
sudo ./scripts/secure_laptop.sh --dry-run
```

Non-interactive (assume yes):

```bash
sudo ./scripts/secure_laptop.sh --non-interactive
```

Enable nftables (optional). If you want nftables instead of UFW, use:

```bash
sudo ./scripts/secure_laptop.sh --enable-nft --no-ufw
```

Safety notes
------------

- Run from a local console or ensure you have alternative recovery access before changing firewall rules remotely.
- The script attempts to be idempotent and backs up files it changes (`*.bak-YYYYMMDD-HHMMSS`).
- On systems not using Debian/Ubuntu, package manager detection is best-effort; you may need to install packages manually.
- Enabling nftables alongside UFW can cause conflicts. Prefer one firewall method.

Next steps
----------

- Review the script before running. Pay attention to the SSH port detection and rules.
- If you customize nftables rules, edit `/etc/nftables.conf` and then run `systemctl restart nftables`.
