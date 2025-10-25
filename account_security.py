"""Account and identity security auditing utilities."""

from __future__ import annotations

import datetime
import grp
import os
import pwd
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any


DEFAULT_SYMLINK_SCAN_PATHS = [Path("/home"), Path("/tmp"), Path("/var/tmp")]
SENSITIVE_PREFIXES = (
	"/etc",
	"/root",
	"/bin",
	"/sbin",
	"/usr/bin",
	"/usr/sbin",
)


def _maybe_sudo() -> List[str]:
	if os.geteuid() == 0:
		return []
	if shutil.which("sudo"):
		return ["sudo"]
	return []


def _run(cmd: List[str], dry_run: bool = False) -> subprocess.CompletedProcess:
	if dry_run:
		return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
	return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _protected_users(supplemental: Optional[List[str]] = None) -> List[str]:
	protected = {"root"}
	for env_var in ("SUDO_USER", "USER", "LOGNAME"):
		value = os.environ.get(env_var)
		if value:
			protected.add(value)
	if supplemental:
		protected.update(supplemental)
	return sorted(protected)


def _protected_groups(supplemental: Optional[List[str]] = None) -> List[str]:
	protected = {"root", "sudo", "adm"}
	current = os.environ.get("USER")
	if current:
		protected.add(current)
	if supplemental:
		protected.update(supplemental)
	return sorted(protected)


def review_accounts(
	allowed_users: Optional[List[str]] = None,
	allowed_groups: Optional[List[str]] = None,
	base_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
	allowed_user_set = set(_protected_users(allowed_users))
	allowed_group_set = set(_protected_groups(allowed_groups))

	suspect_users: List[Dict[str, Any]] = []
	for entry in pwd.getpwall():
		if entry.pw_uid < 1000:
			continue
		if entry.pw_name in allowed_user_set:
			continue
		if entry.pw_shell in {"/usr/sbin/nologin", "/bin/false"}:
			continue
		suspect_users.append(
			{
				"name": entry.pw_name,
				"uid": entry.pw_uid,
				"home": entry.pw_dir,
				"shell": entry.pw_shell,
			}
		)

	suspect_groups: List[Dict[str, Any]] = []
	for entry in grp.getgrall():
		if entry.gr_gid < 1000:
			continue
		if entry.gr_name in allowed_group_set:
			continue
		members = list(entry.gr_mem)
		if members:
			continue
		suspect_groups.append(
			{
				"name": entry.gr_name,
				"gid": entry.gr_gid,
				"members": members,
			}
		)

	symlink_info = scan_suspicious_symlinks(base_paths=base_paths)

	return {
		"suspect_users": suspect_users,
		"suspect_groups": suspect_groups,
		"suspicious_symlinks": symlink_info,
	}


def remove_user(username: str, *, dry_run: bool = False, remove_home: bool = True) -> Dict[str, Any]:
	cmd = _maybe_sudo() + ["userdel"]
	if remove_home:
		cmd.append("-r")
	cmd.append(username)
	result = _run(cmd, dry_run=dry_run)
	success = result.returncode == 0
	return {
		"success": success,
		"command": " ".join(cmd),
		"stderr": result.stderr.strip(),
		"username": username,
		"removed_home": remove_home,
		"dry_run": dry_run,
	}


def remove_group(groupname: str, *, dry_run: bool = False) -> Dict[str, Any]:
	cmd = _maybe_sudo() + ["groupdel", groupname]
	result = _run(cmd, dry_run=dry_run)
	success = result.returncode == 0
	return {
		"success": success,
		"command": " ".join(cmd),
		"stderr": result.stderr.strip(),
		"groupname": groupname,
		"dry_run": dry_run,
	}


def scan_suspicious_symlinks(base_paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
	paths = base_paths or [str(p) for p in DEFAULT_SYMLINK_SCAN_PATHS]
	suspicious: List[Dict[str, Any]] = []

	for base in paths:
		base_path = Path(base)
		if not base_path.exists():
			continue
		try:
			for candidate in base_path.rglob("*"):
				if not candidate.is_symlink():
					continue
				reasons: List[str] = []
				target_raw = os.readlink(candidate)
				resolved = os.path.realpath(candidate)
				if not os.path.exists(resolved):
					reasons.append("target missing")
				for prefix in SENSITIVE_PREFIXES:
					if resolved.startswith(prefix) and not str(candidate).startswith(prefix):
						reasons.append(f"points into {prefix}")
						break
				if not reasons:
					continue
				suspicious.append(
					{
						"path": str(candidate),
						"target": resolved,
						"reasons": reasons,
					}
				)
		except Exception:
			continue

	return suspicious


def _create_archive(target: str, archive_path: Path, dry_run: bool) -> Dict[str, Any]:
	if dry_run:
		return {
			"success": True,
			"command": f"tar -czf {archive_path} {target}",
			"stderr": "",
		}

	if not os.path.exists(target):
		return {
			"success": False,
			"command": "",
			"stderr": "Target missing; archive not created",
		}

	archive_path.parent.mkdir(parents=True, exist_ok=True)

	parent = os.path.dirname(target) or "."
	name = os.path.basename(target)
	cmd = _maybe_sudo() + ["tar", "-czf", str(archive_path), "-C", parent, name]
	result = _run(cmd, dry_run=False)
	return {
		"success": result.returncode == 0,
		"command": " ".join(cmd),
		"stderr": result.stderr.strip(),
	}


def _antivirus_scan(path: Path, dry_run: bool, use_antivirus: bool) -> Dict[str, Any]:
	if not use_antivirus:
		return {
			"success": True,
			"command": "",
			"stderr": "Antivirus scan skipped by configuration",
		}
	if dry_run:
		return {
			"success": True,
			"command": f"clamscan {path}",
			"stderr": "",
		}
	if shutil.which("clamscan") is None:
		return {
			"success": False,
			"command": "",
			"stderr": "clamscan not available",
		}
	cmd = _maybe_sudo() + ["clamscan", str(path)]
	result = _run(cmd, dry_run=False)
	return {
		"success": result.returncode in {0, 1},
		"command": " ".join(cmd),
		"stderr": result.stderr.strip(),
		"infected": result.returncode == 1,
	}


def neutralize_symlink(
	symlink_path: str,
	*,
	dry_run: bool = False,
	archive_dir: Optional[str] = None,
	use_antivirus: bool = True,
) -> Dict[str, Any]:
	path = Path(symlink_path)
	if not path.is_symlink():
		return {
			"success": False,
			"message": f"Not a symlink: {symlink_path}",
			"dry_run": dry_run,
		}

	target_raw = os.readlink(path)
	resolved = os.path.realpath(path)
	timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
	archive_directory = Path(archive_dir) if archive_dir else Path("/tmp")
	archive_path = archive_directory / f"suspicious_symlink_{path.name}_{timestamp}.tar.gz"

	archive_result = _create_archive(resolved, archive_path, dry_run)
	antivirus_result = _antivirus_scan(archive_path, dry_run, use_antivirus)

	remove_cmd = _maybe_sudo() + ["rm", "-f", str(path)]
	remove_result = _run(remove_cmd, dry_run=dry_run)

	success = (
		archive_result.get("success", False)
		and antivirus_result.get("success", True)
		and remove_result.returncode == 0
	)

	if dry_run:
		message = "Symlink would be archived, scanned, and removed"
	else:
		message = "Symlink neutralized" if success else "Symlink neutralization encountered issues"

	return {
		"success": success,
		"message": message,
		"symlink": str(path),
		"target": resolved,
		"archive": str(archive_path),
		"archive_result": archive_result,
		"antivirus_result": antivirus_result,
		"remove_command": " ".join(remove_cmd),
		"remove_stderr": remove_result.stderr.strip(),
		"dry_run": dry_run,
	}


def cleanup_accounts(
	*,
	auto_remove: bool = False,
	break_symlinks: bool = False,
	dry_run: bool = False,
	allowed_users: Optional[List[str]] = None,
	allowed_groups: Optional[List[str]] = None,
	base_paths: Optional[List[str]] = None,
	archive_dir: Optional[str] = None,
	use_antivirus: bool = True,
) -> Dict[str, Any]:
	review = review_accounts(
		allowed_users=allowed_users,
		allowed_groups=allowed_groups,
		base_paths=base_paths,
	)

	actions: List[Dict[str, Any]] = []
	errors: List[str] = []

	if auto_remove:
		for candidate in review["suspect_users"]:
			result = remove_user(candidate["name"], dry_run=dry_run)
			actions.append(result)
			if not result["success"]:
				errors.append(f"Failed to remove user {candidate['name']}: {result['stderr']}")
		for candidate in review["suspect_groups"]:
			result = remove_group(candidate["name"], dry_run=dry_run)
			actions.append(result)
			if not result["success"]:
				errors.append(f"Failed to remove group {candidate['name']}: {result['stderr']}")

	if break_symlinks:
		for candidate in review["suspicious_symlinks"]:
			result = neutralize_symlink(
				candidate["path"],
				dry_run=dry_run,
				archive_dir=archive_dir,
				use_antivirus=use_antivirus,
			)
			actions.append(result)
			if not result["success"]:
				errors.append(f"Failed to neutralize {candidate['path']}: {result.get('message')}")

	success = not errors
	if dry_run:
		message = (
			"Account cleanup would be performed"
			if (auto_remove or break_symlinks)
			else "Account audit would be performed"
		)
	else:
		if auto_remove or break_symlinks:
			message = "Account cleanup completed" if success else "Account cleanup encountered issues"
		else:
			message = "Account audit completed (no changes applied)"

	return {
		"success": success,
		"message": message,
		"review": review,
		"actions": actions,
		"errors": errors,
		"dry_run": dry_run,
		"pending_users": [entry["name"] for entry in review["suspect_users"]],
		"pending_groups": [entry["name"] for entry in review["suspect_groups"]],
		"pending_symlinks": [entry["path"] for entry in review["suspicious_symlinks"]],
	}


def get_account_security_summary() -> str:
	data = review_accounts()
	lines = [
		"Account security summary:",
		f"- Suspect users: {len(data['suspect_users'])}",
		f"- Empty groups: {len(data['suspect_groups'])}",
		f"- Suspicious symlinks: {len(data['suspicious_symlinks'])}",
		"Use cleanup_accounts to remove or neutralize findings.",
	]
	return "\n".join(lines)
