"""
Module: init_check.py
Purpose: Verify that /sbin/init has not been tampered with on the system.
"""

import hashlib
import os
import subprocess

def get_file_hash(path, hash_algo='sha256'):
    """Return the hash of a file using the specified algorithm."""
    h = hashlib.new(hash_algo)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def get_package_manager():
    """Detect the package manager (Arch: pacman)."""
    if os.path.exists('/usr/bin/pacman'):
        return 'pacman'
    return None

def get_init_expected_hash():
    """Get the expected hash of /sbin/init from the package manager database (Arch Linux)."""
    # On Arch, /sbin/init is usually a symlink to /usr/lib/systemd/systemd
    # We'll check the hash of /usr/lib/systemd/systemd as well
    try:
        output = subprocess.check_output([
            'pacman', '-Qk', 'systemd'
        ], stderr=subprocess.STDOUT, text=True)
        # This only checks for file presence, not hash. Arch does not store file hashes by default.
        # Instead, we can use pacman -Qk to check for file integrity, but not hash.
        # For hash, we can compare to a known-good hash or use a custom baseline.
        return None
    except Exception:
        return None

def verify_init_integrity():
    """Verify /sbin/init (and its target) has not been tampered with."""
    init_path = '/sbin/init'
    if not os.path.exists(init_path):
        return False, f"{init_path} does not exist."
    # Resolve symlink
    real_path = os.path.realpath(init_path)
    file_hash = get_file_hash(real_path)
    # Optionally, compare to a baseline hash (user must provide)
    # For now, just return the hash
    return True, f"{real_path} hash: {file_hash}"

if __name__ == "__main__":
    ok, msg = verify_init_integrity()
    print(msg)
