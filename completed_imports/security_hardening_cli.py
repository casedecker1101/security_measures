#!/usr/bin/env python3
"""
Standalone Security Hardening Script
This provides a command-line interface to the security hardening functions
"""

import sys
import argparse
from typing import Dict, List, Any
from flatline_dixie.checks import (
    ssh_hardening_check,
    smb_hardening_check, 
    system_hardening_check,
    anti_spying_check,
    inetd_check,
    block_remote_apps,
    loopback_restriction,
    account_security,
    rootkit_remediation,
    custom_hardening,
)
from flatline_dixie.checks.security_hardening import (
    scan_rootkits,
    verify_boot_partitions,
    install_security_tools,
    run_full_hardening,
    remediate_rootkit_findings,
    cleanup_accounts as cleanup_accounts_task,
    install_firewall_packages as install_firewall_packages_task,
)


def main():
    parser = argparse.ArgumentParser(
        description='Flatline Dixie Security Hardening System'
    )
    
    parser.add_argument(
        'action',
        choices=[
            'check_ssh', 'check_smb', 'check_system', 'check_anti_spying', 'audit_accounts',
                'harden_ssh', 'harden_smb', 'harden_system', 'harden_inetd', 'harden_remote_apps', 'harden_loopback', 'cleanup_accounts', 'remediate_rootkits', 'harden_all', 'disable_spying',
                    'remove_user', 'remove_group', 'audit_symlinks', 'remediate_symlink',
                    'scan_rootkits', 'verify_boot', 'install_tools',
                        'install_firewall_tools',
                    'summary_ssh', 'summary_smb', 'summary_system', 'summary_inetd', 'summary_remote_apps', 'summary_loopback', 'summary_accounts', 'summary_rootkit', 'summary_anti_spying',
                    'firewall_export', 'harden_firewall', 'summary_firewall', 'custom_hardening'
        ],
        help='Action to perform'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without executing (for hardening actions)'
    )

    parser.add_argument('--user', help='Username to target for account operations')
    parser.add_argument('--group', help='Group name to target for account operations')
    parser.add_argument('--path', help='Symlink path to audit or remediate')
    parser.add_argument('--archive-dir', help='Directory to store compressed evidence archives')
    parser.add_argument('--allowed-user', action='append', dest='allowed_users', help='Protect user from removal (can be repeated)')
    parser.add_argument('--allowed-group', action='append', dest='allowed_groups', help='Protect group from removal (can be repeated)')
    parser.add_argument('--base-path', action='append', dest='base_paths', help='Additional path to scan for suspicious symlinks (can be repeated)')
    parser.add_argument('--auto-remove', action='store_true', help='Automatically remove suspicious users/groups during cleanup')
    parser.add_argument('--break-symlinks', action='store_true', help='Break suspicious symlinks during cleanup')
    parser.add_argument('--skip-antivirus', action='store_true', help='Skip antivirus scanning when handling suspicious files')
    parser.add_argument('--keep-home', action='store_true', help='Preserve home directory when removing users')
    parser.add_argument('--custom-task', action='append', dest='custom_tasks', help='Custom hardening task key to run (repeatable)')
    parser.add_argument('--custom-no-prompt', action='store_true', help='Fail if no custom tasks are provided for custom_hardening action')
    
    args = parser.parse_args()
    
    # Check actions (non-destructive)
    if args.action == 'check_ssh':
        ok, msg = ssh_hardening_check.verify_ssh_hardening()
        print(f"SSH Security: {'OK' if ok else 'ISSUES'}")
        print(msg)
        return 0 if ok else 1
    
    elif args.action == 'check_smb':
        ok, msg = smb_hardening_check.verify_smb_security()
        print(f"SMB Security: {'OK' if ok else 'ISSUES'}")
        print(msg)
        return 0 if ok else 1
    
    elif args.action == 'check_system':
        ok, msg = system_hardening_check.verify_system_hardening()
        print(f"System Security: {'OK' if ok else 'ISSUES'}")
        print(msg)
        return 0 if ok else 1
    
    elif args.action == 'check_anti_spying':
        ok, msg = anti_spying_check.verify_anti_spying()
        print(f"Anti-Spying Protection: {'OK' if ok else 'ISSUES'}")
        print(msg)
        return 0 if ok else 1

    elif args.action == 'audit_accounts':
        review = account_security.review_accounts(
            allowed_users=args.allowed_users,
            allowed_groups=args.allowed_groups,
            base_paths=args.base_paths,
        )
        suspect_users = review['suspect_users']
        suspect_groups = review['suspect_groups']
        suspicious_symlinks = review['suspicious_symlinks']

        print("Account audit findings:")
        if suspect_users:
            print("- Users requiring review:")
            for user in suspect_users:
                print(f"    * {user['name']} (uid={user['uid']}, home={user['home']}, shell={user['shell']})")
        else:
            print("- No user anomalies detected.")

        if suspect_groups:
            print("- Groups without members:")
            for group in suspect_groups:
                print(f"    * {group['name']} (gid={group['gid']})")
        else:
            print("- No empty high-GID groups detected.")

        if suspicious_symlinks:
            print("- Suspicious symlinks:")
            for link in suspicious_symlinks:
                reasons = ", ".join(link['reasons'])
                print(f"    * {link['path']} -> {link['target']} ({reasons})")
        else:
            print("- No suspicious symlinks detected.")

        has_findings = bool(suspect_users or suspect_groups or suspicious_symlinks)
        return 1 if has_findings else 0
    
    # Hardening actions (potentially destructive)
    elif args.action == 'harden_ssh':
        success, msg = ssh_hardening_check.apply_ssh_hardening(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "applied"
        print(f"SSH hardening {action_type}: {'SUCCESS' if success else 'FAILED'}")
        print(msg)
        return 0 if success else 1
    
    elif args.action == 'harden_smb':
        success, msg = smb_hardening_check.apply_smb_hardening(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "applied"
        print(f"SMB hardening {action_type}: {'SUCCESS' if success else 'FAILED'}")
        print(msg)
        return 0 if success else 1
    
    elif args.action == 'harden_system':
        success, msg = system_hardening_check.apply_full_hardening(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "applied"
        print(f"Full system hardening {action_type}: {'SUCCESS' if success else 'FAILED'}")
        print(msg)
        return 0 if success else 1

    elif args.action == 'harden_inetd':
        success, msg = inetd_check.apply_inetd_hardening(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "applied"
        print(f"inetd/xinetd hardening {action_type}: {'SUCCESS' if success else 'FAILED'}")
        print(msg)
        return 0 if success else 1

    elif args.action == 'harden_remote_apps':
        result = block_remote_apps.apply_remote_app_block(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "applied"
        print(f"Remote application blocking {action_type}: {'SUCCESS' if result.get('success') else 'FAILED'}")
        print(result.get('message', ''))
        if result.get('errors'):
            print("Errors:")
            for err in result['errors']:
                print(f"  - {err}")
        return 0 if result.get('success') else 1

    elif args.action == 'harden_loopback':
        result = loopback_restriction.apply_loopback_block(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "applied"
        print(f"Loopback restriction {action_type}: {'SUCCESS' if result.get('success') else 'FAILED'}")
        print(result.get('message', ''))
        errors = result.get('errors', [])
        if errors and isinstance(errors, list):
            print("Errors:")
            for err in errors:
                print(f"  - {err}")
        return 0 if result.get('success') else 1

    elif args.action == 'cleanup_accounts':
        result = cleanup_accounts_task(
            auto_remove=args.auto_remove,
            break_symlinks=args.break_symlinks,
            dry_run=args.dry_run,
            allowed_users=args.allowed_users,
            allowed_groups=args.allowed_groups,
            base_paths=args.base_paths,
            archive_dir=args.archive_dir,
            use_antivirus=not args.skip_antivirus,
        )
        action_type = "would be executed" if args.dry_run else "completed"
        mode_label = "cleanup" if (args.auto_remove or args.break_symlinks) else "audit"
        print(f"Account {mode_label} {action_type}: {'SUCCESS' if result.get('success') else 'FAILED'}")
        print(result.get('message', ''))
        if result.get('errors'):
            print("Errors:")
            for err in result['errors']:
                print(f"  - {err}")
        return 0 if result.get('success') else 1

    elif args.action == 'custom_hardening':
        selected = args.custom_tasks
        if not selected:
            if args.custom_no_prompt:
                print("No custom tasks provided.")
                return 1
            selected = custom_hardening.prompt_for_tasks()

        result = custom_hardening.run_custom_hardening(selected or [], dry_run=args.dry_run)

        for entry in result.get('results', []):
            status = 'OK' if entry.get('success') else 'FAIL'
            print(f"[{status}] {entry.get('name')}: {entry.get('message')}")
            details = entry.get('details', {})
            for key, value in details.items():
                print(f"    {key}: {value}")
            if entry.get('error'):
                print(f"    error: {entry['error']}")

        if result.get('missing'):
            print("Unrecognized tasks: " + ", ".join(result['missing']))

        message = result.get('message')
        if message:
            print(message)

        return 0 if result.get('success') else 1

    elif args.action == 'remove_user':
        if not args.user:
            print("Error: --user is required for remove_user")
            return 1
        result = account_security.remove_user(args.user, dry_run=args.dry_run, remove_home=not args.keep_home)
        status = 'SUCCESS' if result.get('success') else 'FAILED'
        verb = "would be removed" if args.dry_run else "removed"
        print(f"User {args.user} {verb}: {status}")
        if result.get('stderr'):
            print(result['stderr'])
        return 0 if result.get('success') else 1

    elif args.action == 'remove_group':
        if not args.group:
            print("Error: --group is required for remove_group")
            return 1
        result = account_security.remove_group(args.group, dry_run=args.dry_run)
        status = 'SUCCESS' if result.get('success') else 'FAILED'
        verb = "would be removed" if args.dry_run else "removed"
        print(f"Group {args.group} {verb}: {status}")
        if result.get('stderr'):
            print(result['stderr'])
        return 0 if result.get('success') else 1

    elif args.action == 'audit_symlinks':
        findings = account_security.scan_suspicious_symlinks(base_paths=args.base_paths)
        if findings:
            print("Suspicious symlinks detected:")
            for entry in findings:
                reasons = ", ".join(entry['reasons'])
                print(f"- {entry['path']} -> {entry['target']} ({reasons})")
        else:
            print("No suspicious symlinks found.")
        return 1 if findings else 0

    elif args.action == 'remediate_symlink':
        if not args.path:
            print("Error: --path is required for remediate_symlink")
            return 1
        result = account_security.neutralize_symlink(
            args.path,
            dry_run=args.dry_run,
            archive_dir=args.archive_dir,
            use_antivirus=not args.skip_antivirus,
        )
        status = 'SUCCESS' if result.get('success') else 'FAILED'
        verb = "would be neutralized" if args.dry_run else "neutralized"
        print(f"Symlink {args.path} {verb}: {status}")
        print(result.get('message', ''))
        if result.get('antivirus_result'):
            av = result['antivirus_result']
            if av.get('command'):
                print(f"Antivirus command: {av['command']}")
            if av.get('stderr'):
                print(f"Antivirus output: {av['stderr']}")
        if result.get('remove_stderr'):
            print(f"Removal stderr: {result['remove_stderr']}")
        return 0 if result.get('success') else 1

    elif args.action == 'remediate_rootkits':
        result = remediate_rootkit_findings(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "executed"
        print(f"Rootkit remediation {action_type}: {'SUCCESS' if result.get('success') else 'FAILED'}")
        print(result.get('message', ''))
        for step in result.get('steps', []):
            status = 'OK' if step.get('success') else 'ISSUES'
            print(f"  - {step.get('action')}: {status} ({step.get('message')})")
            for cmd in step.get('commands', []):
                print(f"      cmd: {cmd}")
            for err in step.get('errors', []):
                print(f"      err: {err}")
        return 0 if result.get('success') else 1
    
    elif args.action == 'disable_spying':
        success, msg = anti_spying_check.apply_anti_spying_hardening(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "applied"
        print(f"Anti-spying measures {action_type}: {'SUCCESS' if success else 'FAILED'}")
        print(msg)
        return 0 if success else 1
    
    elif args.action == 'harden_all':
        result = run_full_hardening(dry_run=args.dry_run)
        action_type = "would be applied" if args.dry_run else "applied"
        print(f"Complete hardening {action_type}: {'SUCCESS' if result['success'] else 'FAILED'}")
        print(result['message'])
        if result.get('report'):
            print("\nDetailed Report:")
            print(result['report'])
        return 0 if result['success'] else 1
    
    # Security scanning actions
    elif args.action == 'scan_rootkits':
        result = scan_rootkits(dry_run=args.dry_run)
        print(f"Rootkit scan: {result['message']}")
        if result.get('results'):
            print("Scan Results:")
            for tool, data in result['results'].items():
                if data.get('installed'):
                    print(f"  {tool}: {data.get('output', 'No output')}")
                else:
                    print(f"  {tool}: Not installed")
        return 0 if result['success'] else 1
    
    elif args.action == 'verify_boot':
        result = verify_boot_partitions(dry_run=args.dry_run)
        print(f"Boot verification: {result['message']}")
        if result.get('partitions'):
            print("Partition Status:")
            for partition, data in result['partitions'].items():
                if data.get('exists'):
                    clean = "CLEAN" if data.get('clean') else "ISSUES"
                    print(f"  {partition}: {clean}")
                else:
                    print(f"  {partition}: Not found")
        return 0 if result['success'] else 1
    
    elif args.action == 'install_tools':
        result = install_security_tools(dry_run=args.dry_run)
        print(f"Security tools installation: {result['message']}")
        if result.get('tools'):
            print(f"Tools: {', '.join(result['tools'])}")
        return 0 if result['success'] else 1

    elif args.action == 'install_firewall_tools':
        result = install_firewall_packages_task(dry_run=args.dry_run)
        action_type = "would be ensured" if args.dry_run else "ensured"
        print(f"Firewall tooling {action_type}: {'SUCCESS' if result.get('success') else 'FAILED'}")
        for step in result.get('steps', []):
            status = 'OK' if step.get('success') else 'ISSUES'
            print(f"  - {step.get('name')}: {status} ({step.get('message')})")
            stderr = step.get('stderr')
            if stderr:
                print(f"      stderr: {stderr}")
            for err in step.get('errors', []):
                print(f"      err: {err}")
        return 0 if result.get('success') else 1
    
    # Summary actions
    elif args.action == 'summary_ssh':
        print(ssh_hardening_check.get_ssh_hardening_summary())
        return 0
    
    elif args.action == 'summary_smb':
        print(smb_hardening_check.get_smb_security_summary())
        return 0
    
    elif args.action == 'summary_system':
        print(system_hardening_check.get_system_hardening_summary())
        return 0

    elif args.action == 'summary_inetd':
        print(inetd_check.get_inetd_summary())
        return 0

    elif args.action == 'summary_remote_apps':
        print(block_remote_apps.get_remote_app_summary())
        return 0

    elif args.action == 'summary_loopback':
        print(loopback_restriction.get_loopback_summary())
        return 0

    elif args.action == 'summary_accounts':
        print(account_security.get_account_security_summary())
        return 0

    elif args.action == 'summary_rootkit':
        print(rootkit_remediation.get_rootkit_remediation_summary())
        return 0
    
    elif args.action == 'summary_anti_spying':
        print(anti_spying_check.get_anti_spying_summary())
        return 0

    elif args.action == 'firewall_export':
        from flatline_dixie.checks import firewall_security
        result = firewall_security.export_firewall_security(dry_run=args.dry_run)
        print(result.get('message', 'Firewall export completed'))
        summary = result.get('summary', '')
        if summary and isinstance(summary, str):
            print("\nSummary:\n" + summary)
        return 0 if result.get('success') else 1

    elif args.action == 'harden_firewall':
        from flatline_dixie.checks import firewall_security
        result = firewall_security.apply_firewall_hardening(dry_run=args.dry_run)
        print(result.get('message', 'Firewall hardening completed'))
        actions = result.get('hardening_actions', [])
        if actions and isinstance(actions, list):
            print("\nActions:")
            for action in actions:
                print(f"  - {action}")
        return 0 if result.get('success') else 1

    elif args.action == 'summary_firewall':
        from flatline_dixie.checks import firewall_security
        print(firewall_security.get_firewall_summary())
        return 0
    
    else:
        print(f"Unknown action: {args.action}")
        return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)