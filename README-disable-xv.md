Disable XVideo (Xv) script

What this does

- Writes an Xorg config snippet under /etc/X11/xorg.conf.d/99-disable-xv.conf that disables the XVideo (Xv) extension and prevents the "xv" module from loading.
- This prevents X clients (including XWayland) from using the Xv extension for accelerated video overlay.

How to use

- Dry run (preview):
  sudo ./disable-xv.sh --dry-run

- Install (write the file):
  sudo ./disable-xv.sh

- Apply: logout/login, restart the display manager, or reboot the machine.

Checks and flags

- The script detects whether an X server (Xorg/XWayland) is present. If none is detected it will refuse to write the config unless you pass --force.
- Flags:
  - --dry-run : preview the config without writing.
  - --force   : force writing even if no X server is detected.
  - --verify-only : run verification checks to ensure remote access is disabled (does not write any files).
  - --apply-and-verify : write the config (if needed), apply, and re-run verification.
  - --restart-dm : when used with --apply-and-verify, attempt to restart common display managers to apply the config.
  - --apply-firewall : when used with --apply-and-verify, attempt to add a firewall rule to block TCP 6000 (tries ufw, nft, iptables).
  - --disable-ssh-x11 : when used with --apply-and-verify, set `X11Forwarding no` in `/etc/ssh/sshd_config` and reload SSHD.
  - --revert-firewall : remove firewall rules previously added by this script (best-effort).

Notes and caveats

- This requires root to write to /etc/X11/xorg.conf.d.
- Disabling Xv will affect applications that expect the XVideo extension (some media players may revert to software rendering or other APIs like VA-API/Vulkan/GL).
- XWayland: disabling Xv on the X server side prevents Xv extension availability for XWayland's X server instance; Wayland-native apps are unaffected.
- To revert, remove the installed conf and restart the session:
  sudo rm /etc/X11/xorg.conf.d/99-disable-xv.conf

Disable remote X access (local-only)

This script can also disable remote X access by adding X server options to avoid listening on TCP and to disable XDMCP. The Xorg options are written in the same config file; these are additional and make the X server only available locally:

- DontListen TCP: prevents the X server from listening for remote X connections over TCP (X11 protocol).
- XDMCP is disabled via serverflags/config management for display managers — most modern distributions disable XDMCP by default.

If you use a display manager that may allow XDMCP (rare on modern desktops), check its configuration:

- GDM: check `/etc/gdm/custom.conf` or the gdm config for XDMCP settings and ensure XDMCP is disabled.
- KDM/SDDM: check their respective config files; SDDM does not enable XDMCP by default.

These measures are recommended for security; they do not impact Wayland-native clients, but will prevent remote connections to the X server (including XWayland instances) via the network.

Verification checks

Use the `--verify-only` flag to run a set of checks that confirm the system is locked down from remote viewing. The script verifies:

- The config file `/etc/X11/xorg.conf.d/99-disable-xv.conf` exists and contains the expected options (DontListen TCP and XVideo disabled).
- There are no TCP listeners on port 6000 (X11 default port) as reported by `ss` or `netstat`.
- GDM's `/etc/gdm/custom.conf` is checked for XDMCP enablement (basic scan).
The verification now also checks LightDM, SDDM, and KDM configurations for XDMCP-related settings.

Advanced port scanning

The verification performs an advanced port check for TCP port 6000 (X11). If `ip netns` is available it will scan network namespaces to ensure no namespace has a listener on :6000. This helps detect remote X listeners in more complex networking setups (containers, multiple netns).

Example:

  sudo ./disable-xv.sh --verify-only

Exit codes:

- 0: verification passed
- 2: verification failed (warnings present)

Example (apply and verify, restart DM):

  sudo ./disable-xv.sh --apply-and-verify --restart-dm

Example (apply, block port 6000 via firewall, and disable ssh X11 forwarding):

  sudo ./disable-xv.sh --apply-and-verify --apply-firewall --disable-ssh-x11

Caveats:

- Firewall rules added by the script may not be persistent across reboots depending on the distribution's configuration; use your distribution's firewall/persistence mechanisms to make rules permanent.
- Disabling SSH X11 forwarding modifies `/etc/ssh/sshd_config` and reloads sshd; ensure you have an alternate access method before doing this remotely.
- The script records any firewall changes in `/var/lib/disable-xv/`. Use `--revert-firewall` to attempt to revert the change.

Persistence

On Debian-based systems like Kali, the script attempts to persist firewall rules:

- For iptables: uses `iptables-persistent`/`netfilter-persistent` if available to save rules to `/etc/iptables/rules.v4`.
- For nftables: appends a rule to `/etc/nftables.conf` if present (and makes a backup).

If these mechanisms are not available, the script will add runtime rules and record them in `/var/lib/disable-xv/firewall.*` so you can reapply or remove them at next boot.
Exit mask

When verification fails the script returns a numeric exit code that is a bitmask of failed checks (also emits `SUMMARY:` to stderr). This helps automation quickly detect the categories of failures. Combine parsing of the SUMMARY line or check the exit code.

Summary output

If verification fails the script prints a machine-readable SUMMARY line to stderr in the format:

  SUMMARY:missing_config,port6000_open,gdm_xdmcp,vnc:vino-server,ssh_x11_forwarding

You can parse this in automation to determine which checks failed.

Restart guidance for common display managers

If you prefer to restart the display manager rather than rebooting, here are common systemd service names you can use (run as root or with sudo):

- GDM (GNOME): gdm.service
- SDDM (KDE): sddm.service
- LightDM: lightdm.service
- LXDM: lxdm.service
- XDM: xdm.service

Example (restart GDM):

  sudo systemctl restart gdm.service

Wayland compositors

- Many Wayland compositors (e.g., GNOME Shell, KDE with Wayland) run a compositor that manages the session and may be restarted via the display manager above.
- If you use a non-systemd session or a compositor launched directly from a user session (sway, weston, etc.), log out and log back in or restart the compositor according to its docs.

Runtime alternative

- You can also try to disable Xv at runtime for a running X server by preventing loading of the module or using xprop/policy changes, but this varies by driver and Xorg build. The persistent config is the most reliable.

Systemd unit (optional)

If you'd like the script to be applied automatically at boot (useful for machines where the X server is started after system boot or on headless systems), you can install the provided systemd unit `apply-disable-xv.service`.

Install steps:

1. Copy the script to a system location and make it executable:

  sudo cp disable-xv.sh /usr/local/bin/
  sudo chmod 755 /usr/local/bin/disable-xv.sh

2. Copy the unit file and enable it:

  sudo cp apply-disable-xv.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now apply-disable-xv.service

The unit runs the script once at boot. The Xorg config file itself is persistent on disk, so a systemd unit is optional. If you prefer not to use systemd, just run the script once as root.
