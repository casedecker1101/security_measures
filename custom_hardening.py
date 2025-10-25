"""Custom Hardening orchestrator.

Provides a menu-driven interface for selectively running hardening tasks.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

from flatline_dixie.checks import (
    anti_spying_check,
    block_remote_apps,
    fail2ban_hardening,
    firewall_security,
    inetd_check,
    loopback_restriction,
    smb_hardening_check,
    ssh_hardening_check,
    system_hardening_check,
)
from flatline_dixie.checks.security_hardening import (
    cleanup_accounts as cleanup_accounts_task,
    install_firewall_packages as install_firewall_packages_task,
    install_security_tools,
    remediate_rootkit_findings,
    run_full_hardening,
    scan_rootkits,
    verify_boot_partitions,
)


@dataclass
class HardeningTask:
    key: str
    name: str
    description: str
    runner: Callable[[bool], object]


@dataclass
class TaskResult:
    key: str
    name: str
    success: bool
    message: str
    details: Dict[str, object]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "key": self.key,
            "name": self.name,
            "success": self.success,
            "message": self.message,
        }
        if self.details:
            data["details"] = self.details
        if self.error:
            data["error"] = self.error
        return data


def _runner_call(
    func: Callable[..., object],
    *,
    accepts_dry_run: bool = True,
    **extra_kwargs: object,
) -> Callable[[bool], object]:
    def _call(dry_run: bool) -> object:
        kwargs = dict(extra_kwargs)
        if accepts_dry_run:
            kwargs["dry_run"] = dry_run
        return func(**kwargs)

    return _call


HARDENING_TASKS: Dict[str, HardeningTask] = {
    "harden_ssh": HardeningTask(
        key="harden_ssh",
        name="Harden SSH",
        description="Apply the opinionated SSH configuration.",
        runner=_runner_call(ssh_hardening_check.apply_ssh_hardening),
    ),
    "harden_smb": HardeningTask(
        key="harden_smb",
        name="Harden SMB",
        description="Apply hardening rules for Samba services.",
        runner=_runner_call(smb_hardening_check.apply_smb_hardening),
    ),
    "harden_system": HardeningTask(
        key="harden_system",
        name="System Hardening",
        description="Execute the full system-hardening routine.",
        runner=_runner_call(system_hardening_check.apply_full_hardening),
    ),
    "harden_inetd": HardeningTask(
        key="harden_inetd",
        name="inetd/xinetd Hardening",
        description="Disable inetd/xinetd services and lock configurations.",
        runner=_runner_call(inetd_check.apply_inetd_hardening),
    ),
    "block_remote_apps": HardeningTask(
        key="block_remote_apps",
        name="Block Remote Apps",
        description="Apply remote application blocking policies.",
        runner=_runner_call(block_remote_apps.apply_remote_app_block),
    ),
    "restrict_loopback": HardeningTask(
        key="restrict_loopback",
        name="Restrict Loopback",
        description="Apply loopback interface restrictions.",
        runner=_runner_call(loopback_restriction.apply_loopback_block),
    ),
    "cleanup_accounts": HardeningTask(
        key="cleanup_accounts",
        name="Cleanup Accounts",
        description="Run account cleanup with default safety settings.",
        runner=_runner_call(
            cleanup_accounts_task,
            auto_remove=False,
            break_symlinks=False,
            allowed_users=None,
            allowed_groups=None,
            base_paths=None,
            archive_dir=None,
            use_antivirus=True,
        ),
    ),
    "anti_spying": HardeningTask(
        key="anti_spying",
        name="Disable Spying",
        description="Apply anti-spying mitigations.",
        runner=_runner_call(anti_spying_check.apply_anti_spying_hardening),
    ),
    "remediate_rootkits": HardeningTask(
        key="remediate_rootkits",
        name="Remediate Rootkits",
        description="Remediate detected rootkit findings.",
        runner=_runner_call(remediate_rootkit_findings),
    ),
    "install_security_tools": HardeningTask(
        key="install_security_tools",
        name="Install Security Tools",
        description="Ensure core security tooling is installed.",
        runner=_runner_call(install_security_tools),
    ),
    "install_firewall_tools": HardeningTask(
        key="install_firewall_tools",
        name="Install Firewall Tooling",
        description="Install firewall helper packages.",
        runner=_runner_call(install_firewall_packages_task),
    ),
    "harden_firewall": HardeningTask(
        key="harden_firewall",
        name="Harden Firewall",
        description="Apply comprehensive firewall hardening.",
        runner=_runner_call(firewall_security.apply_firewall_hardening),
    ),
    "configure_fail2ban": HardeningTask(
        key="configure_fail2ban",
        name="Configure Fail2Ban",
        description="Configure Fail2Ban using the bundled policy.",
        runner=_runner_call(fail2ban_hardening.apply_fail2ban_hardening),
    ),
    "scan_rootkits": HardeningTask(
        key="scan_rootkits",
        name="Scan for Rootkits",
        description="Run rootkit detection tooling.",
        runner=_runner_call(scan_rootkits),
    ),
    "verify_boot": HardeningTask(
        key="verify_boot",
        name="Verify Boot",
        description="Verify integrity of boot partitions.",
        runner=_runner_call(verify_boot_partitions),
    ),
    "run_full_hardening": HardeningTask(
        key="run_full_hardening",
        name="Full Hardening",
        description="Execute the monolithic hardening pipeline.",
        runner=_runner_call(run_full_hardening),
    ),
}


__all__ = [
    "HardeningTask",
    "TaskResult",
    "get_available_tasks",
    "run_custom_hardening",
    "prompt_for_tasks",
    "main",
]


def get_available_tasks() -> List[HardeningTask]:
    return list(HARDENING_TASKS.values())


def _normalize_result(task: HardeningTask, raw: object) -> TaskResult:
    details: Dict[str, object] = {}
    if isinstance(raw, TaskResult):
        return raw

    if isinstance(raw, tuple) and len(raw) == 2:
        success = bool(raw[0])
        message = str(raw[1])
    elif isinstance(raw, dict):
        success = bool(raw.get("success", False))
        message = str(raw.get("message", task.name))
        details = {k: v for k, v in raw.items() if k not in {"success", "message"}}
    elif isinstance(raw, bool):
        success = raw
        message = task.name if raw else f"{task.name} failed"
    elif raw is None:
        success = True
        message = f"{task.name} completed"
    else:
        success = True
        message = str(raw)
        details = {"raw_result": raw}

    if not message:
        message = task.description

    return TaskResult(
        key=task.key,
        name=task.name,
        success=success,
        message=message,
        details=details,
    )


def _execute_task(task: HardeningTask, dry_run: bool) -> TaskResult:
    try:
        try:
            raw = task.runner(dry_run)
        except TypeError:
            raw = task.runner(dry_run=dry_run)
    except Exception as exc:  # pragma: no cover - defensive guard
        return TaskResult(
            key=task.key,
            name=task.name,
            success=False,
            message=f"{task.name} encountered an error",
            details={},
            error=str(exc),
        )

    return _normalize_result(task, raw)


def run_custom_hardening(
    selected_keys: Sequence[str],
    *,
    dry_run: bool = False,
) -> Dict[str, object]:
    if not selected_keys:
        return {
            "success": False,
            "results": [],
            "missing": [],
            "selected": [],
            "message": "No tasks selected.",
        }

    results: List[TaskResult] = []
    missing: List[str] = []

    for key in selected_keys:
        task = HARDENING_TASKS.get(key)
        if not task:
            missing.append(key)
            continue
        results.append(_execute_task(task, dry_run))

    overall_success = bool(results) and all(result.success for result in results) and not missing

    payload: Dict[str, object] = {
        "success": overall_success,
        "results": [result.to_dict() for result in results],
        "missing": missing,
        "selected": list(selected_keys),
    }

    if not results:
        payload["message"] = "No valid tasks were selected."
    elif missing:
        payload["message"] = "Some tasks were not recognized."
    elif overall_success:
        payload["message"] = "Custom hardening completed."
    else:
        payload["message"] = "At least one task failed."

    return payload


def _print_task_list(stream: Optional[object] = None) -> None:
    target = stream or sys.stdout
    for idx, task in enumerate(get_available_tasks(), start=1):
        target.write(f"{idx}. {task.name} ({task.key})\n")
        target.write(f"   {task.description}\n")


def _parse_selection(selection: str, tasks: Sequence[HardeningTask]) -> List[str]:
    tokens = [token.strip() for token in selection.replace(",", " ").split() if token.strip()]
    chosen: List[str] = []
    seen: set[str] = set()

    for token in tokens:
        key: Optional[str] = None
        if token.isdigit():
            idx = int(token) - 1
            if 0 <= idx < len(tasks):
                key = tasks[idx].key
        elif token in HARDENING_TASKS:
            key = token

        if key and key not in seen:
            seen.add(key)
            chosen.append(key)

    return chosen


def prompt_for_tasks() -> List[str]:
    tasks = get_available_tasks()
    if not tasks:
        return []

    while True:
        print("Available hardening tasks:")
        for idx, task in enumerate(tasks, start=1):
            print(f"  {idx}. {task.name} ({task.key}) - {task.description}")

        selection = input("Select tasks (numbers or keys, comma separated, blank to cancel): ").strip()
        if not selection or selection.lower() in {"q", "quit", "exit"}:
            return []

        keys = _parse_selection(selection, tasks)
        if keys:
            return keys

        print("No valid selections detected. Try again.\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run selected hardening tasks.")
    parser.add_argument("--list", action="store_true", help="List available tasks and exit.")
    parser.add_argument("--tasks", nargs="+", help="Task keys to run; prompts if omitted.")
    parser.add_argument("--dry-run", action="store_true", help="Use dry-run mode when supported.")
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Skip interactive selection and fail if no tasks are provided.",
    )

    args = parser.parse_args(argv)

    if args.list:
        _print_task_list()
        return 0

    selected: Optional[Sequence[str]] = args.tasks
    if not selected:
        if args.no_prompt:
            print("No tasks specified.")
            return 1
        selected = prompt_for_tasks()

    result = run_custom_hardening(selected or [], dry_run=args.dry_run)

    for entry in result.get("results", []):
        status = "OK" if entry.get("success") else "FAIL"
        print(f"[{status}] {entry.get('name')}: {entry.get('message')}")
        details = entry.get("details", {})
        for key, value in details.items():
            print(f"    {key}: {value}")
        if entry.get("error"):
            print(f"    error: {entry['error']}")

    if result.get("missing"):
        print("Unrecognized tasks: " + ", ".join(result["missing"]))

    message = result.get("message")
    if message:
        print(message)

    return 0 if result.get("success") else 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main())
