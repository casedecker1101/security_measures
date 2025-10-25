"""Flatline Dixie Mark I - Custom PyQt5 control console (GUI v1.1)."""

import sys
import os
import json
import html
import pprint
import shlex
import shutil
import datetime
import base64
import secrets
import hashlib
import tempfile
import subprocess
import signal
from pathlib import Path
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Tuple, cast


def _ensure_aesgcm() -> "AESGCM":  # type: ignore[name-defined]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        return AESGCM
    except ImportError as _initial_exc:  # pragma: no cover - dependency bootstrap
        install_cmd = [sys.executable, "-m", "pip", "install", "cryptography"]
        try:
            print("[Flatline Dixie] Installing required dependency: cryptography")
            subprocess.run(install_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as install_exc:  # pragma: no cover - bootstrap failure
            raise ImportError(
                "The 'cryptography' package is required but could not be installed automatically. "
                "Run 'pip install cryptography' and restart the application."
            ) from install_exc
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
            return AESGCM
        except Exception as import_exc:
            raise ImportError(
                "The 'cryptography' package is required but still unavailable after attempting installation."
            ) from import_exc


AESGCM = _ensure_aesgcm()


def _ensure_pyqt5() -> None:
    try:
        import PyQt5  # type: ignore  # noqa: F401
        return
    except ImportError:
        install_cmd = [sys.executable, "-m", "pip", "install", "PyQt5"]
        try:
            print("[Flatline Dixie] Installing required dependency: PyQt5")
            subprocess.run(install_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as install_exc:  # pragma: no cover - bootstrap failure
            raise ImportError(
                "PyQt5 is required but could not be installed automatically. "
                "Run 'pip install PyQt5' and restart the application."
            ) from install_exc
        try:
            import PyQt5  # type: ignore  # noqa: F401
        except Exception as import_exc:  # pragma: no cover - bootstrap failure
            raise ImportError(
                "PyQt5 is required but still unavailable after attempting installation."
            ) from import_exc


_ensure_pyqt5()

GUI_VERSION = "1.1"

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QCloseEvent
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QInputDialog,
    QMessageBox,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QLabel,
    QTabWidget,
    QPlainTextEdit,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QSizePolicy,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QStackedWidget,
    QCheckBox,
    QSplitter,
)


def _ensure_package_path() -> None:
    package_root = Path(__file__).resolve().parent
    repo_root = package_root.parent
    candidate = str(repo_root)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)


_ensure_package_path()

from flatline_dixie import chat
from flatline_dixie.checks import (
    ssh_hardening_check,
    smb_hardening_check,
    system_hardening_check,
    anti_spying_check,
    inetd_check,
    firewall_security,
    firewall_installation,
    block_remote_apps as block_remote_module,
    loopback_restriction,
    account_security,
    rootkit_remediation,
    integrated_security,
    custom_hardening,
)
from flatline_dixie.checks.security_hardening import (
    harden_ssh,
    disable_rdp_vnc,
    secure_smb,
    disable_cameras,
    disable_servers,
    disable_inetd_services,
    block_remote_apps as block_remote_apps_task,
    disable_spying_services as disable_spying_services_task,
    block_loopback as block_loopback_task,
    cleanup_accounts as cleanup_accounts_task,
    remove_passwordless_sudo,
    install_security_tools,
    install_firewall_packages,
    harden_firewall,
    scan_rootkits,
    remediate_rootkit_findings,
    verify_boot_partitions,
)


class CredentialCipher:
    """Simple stream cipher wrapper for storing VPN credentials encrypted at rest.

    This uses a simple XOR keystream derived from a persistent 32-byte key
    written to the provided key path. It's intentionally lightweight because
    it's used only to avoid keeping plaintext credentials on disk; for stronger
    protection use OS keyrings.
    """

    NONCE_SIZE = 16

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        self.key = self._load_or_create_key()

    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        payload = plaintext.encode("utf-8")
        keystream = self._keystream(nonce, len(payload))
        cipher = bytes(p ^ k for p, k in zip(payload, keystream))
        return base64.urlsafe_b64encode(nonce + cipher).decode("ascii")

    def decrypt(self, token: str) -> str:
        if not token:
            return ""
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii"))
        except Exception:
            return ""
        if len(raw) < self.NONCE_SIZE:
            return ""
        nonce = raw[: self.NONCE_SIZE]
        cipher = raw[self.NONCE_SIZE :]
        keystream = self._keystream(nonce, len(cipher))
        plain = bytes(c ^ k for c, k in zip(cipher, keystream))
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError:
            return ""

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            try:
                key = self.key_path.read_bytes()
                if len(key) >= 32:
                    return key[:32]
            except Exception:
                pass
        key = secrets.token_bytes(32)
        try:
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_path.write_bytes(key)
            os.chmod(self.key_path, 0o600)
        except Exception:
            pass
        return key

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            counter_bytes = counter.to_bytes(4, "big")
            block = hashlib.sha256(self.key + nonce + counter_bytes).digest()
            stream.extend(block)
            counter += 1
        return bytes(stream[:length])

class TokenCipher:
    """AES-GCM token cipher wrapper using cryptography's AESGCM.

    Provides encrypt/decrypt helpers for short tokens stored in configs.
    """

    NONCE_SIZE = 12  # 96-bit nonce for AES-GCM

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AESGCM key must be 16/24/32 bytes")
        self.aead = AESGCM(key)

    @staticmethod
    def gen_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(self.NONCE_SIZE)
        ct = self.aead.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.urlsafe_b64encode(nonce + ct).decode("ascii")

    def decrypt(self, token: str) -> str:
        if not token:
            return ""
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii"))
            if len(raw) <= self.NONCE_SIZE:
                return ""
            nonce, ct = raw[:self.NONCE_SIZE], raw[self.NONCE_SIZE:]
            pt = self.aead.decrypt(nonce, ct, None)
            return pt.decode("utf-8")
        except Exception:
            return ""


class TaskRunner(QThread):
    completed = pyqtSignal(str, object)
    failed = pyqtSignal(str, str)

    def __init__(self, task_id: str, func: Callable, *, args: Optional[List[Any]] = None, kwargs: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self.task_id = task_id
        self.func = func
        self.args = args or []
        self.kwargs = kwargs or {}

    def run(self) -> None:  # pragma: no cover - GUI thread execution
        try:
            result = self.func(*self.args, **self.kwargs)
            self.completed.emit(self.task_id, result)
        except Exception as exc:  # pragma: no cover - defensive guard
            self.failed.emit(self.task_id, str(exc))


class FlatlineDixieMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"Flatline Dixie Mark I v{GUI_VERSION} - Security Console")
        self.resize(1100, 760)

        self.task_titles: Dict[str, str] = {}
        self.module_indices: Dict[str, int] = {}
        self.buttons: List[QPushButton] = []
        self.current_thread: Optional[TaskRunner] = None
        self.current_task_id: Optional[str] = None
        self.current_task_title: Optional[str] = None
        self.custom_module_title = "Custom Hardening"
        self.custom_task_id = "custom_hardening_run"
        self.custom_task_list: Optional[QListWidget] = None
        self.custom_select_all: Optional[QCheckBox] = None
        self.custom_dry_run_checkbox: Optional[QCheckBox] = None
        self.custom_output: Optional[QPlainTextEdit] = None
        self.pending_custom_selection: Optional[Dict[str, Any]] = None

        self.copilot_task_id = "copilot_query"
        self.copilot_transcript: Optional[QPlainTextEdit] = None
        self.copilot_prompt_input: Optional[QPlainTextEdit] = None
        self.copilot_cli_command = os.environ.get("COPILOT_CLI_COMMAND", "copilot chat")
        self.copilot_pending_prompt: Optional[str] = None

        self.vpn_store_path = os.path.join(os.path.expanduser("~"), ".flatline_dixie_vpn_profiles.json")
        self.vpn_key_path = Path(os.path.expanduser("~")) / ".flatline_dixie_vpn.key"
        self.vpn_cipher = CredentialCipher(self.vpn_key_path)
        self.vpn_profiles: Dict[str, Dict[str, str]] = {}
        self.vpn_process: Optional[subprocess.Popen] = None
        self.vpn_process_log: Optional[Path] = None
        self.vpn_process_handle = None
        self.vpn_auth_file: Optional[str] = None
        self.vpn_connected_profile: Optional[str] = None
        self.vpn_status_label: Optional[QLabel] = None
        self.vpn_profile_combo: Optional[QComboBox] = None
        self.vpn_profile_path: Optional[QLineEdit] = None
        self.vpn_username_input: Optional[QLineEdit] = None
        self.vpn_password_input: Optional[QLineEdit] = None
        self.vpn_remember_checkbox: Optional[QCheckBox] = None
        self.vpn_connect_btn: Optional[QPushButton] = None
        self.vpn_disconnect_btn: Optional[QPushButton] = None
        self.vpn_save_credentials_btn: Optional[QPushButton] = None
        self.vpn_status_timer = QTimer(self)
        self.vpn_status_timer.setInterval(3000)
        self.vpn_status_timer.timeout.connect(self._poll_vpn_process)

        self.total_tasks_run = 0
        self.successful_tasks = 0
        self.failed_tasks = 0
        self.last_task_title = "None"
        self.last_status_message = "Ready."
        self.original_status_text = "Status: Idle"

        self.overview_tab_index: Optional[int] = None
        self.actions_tab_index: Optional[int] = None
        self.summaries_tab_index: Optional[int] = None
        self.console_tab_index: Optional[int] = None

        self._build_ui()
        self._update_runtime_summary()
        self.append_log(f"Flatline Dixie console ready (GUI v{GUI_VERSION}).")
        self._load_vpn_profiles()
        self.vpn_status_timer.start()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        header_layout = QHBoxLayout()
        title = QLabel(f"<h1 style='margin:0;'>Flatline Dixie Mark I v{GUI_VERSION}</h1>")
        subtitle = QLabel("Adaptive security hardening workstation")
        subtitle.setStyleSheet("color: #8fa1c7;")
        subtitle.setAlignment(
            cast(Qt.Alignment, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        )
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 2)

        overview_widget = self._build_overview_tab()
        actions_widget = self._build_actions_tab()
        summaries_widget = self._build_summaries_tab()
        console_widget = self._build_console_tab()

        self.overview_tab_index = self.tabs.addTab(overview_widget, "Overview")
        self.actions_tab_index = self.tabs.addTab(actions_widget, "Hardening Actions")
        self.summaries_tab_index = self.tabs.addTab(summaries_widget, "Summaries")
        self.console_tab_index = self.tabs.addTab(console_widget, "Assistant Console")

        layout.addWidget(QLabel("Event Log"))
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background-color: #111; color: #ddd; font-family: monospace;")
        layout.addWidget(self.log_view, 3)

    def _build_overview_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        greeting_html = (
            "<p><b>Welcome!</b> Craft focused security runs with the <i>Custom Hardening</i> workspace "
            "or review current posture snapshots below.</p>"
        )

        intro = QLabel(greeting_html)
        intro.setAlignment(cast(Qt.Alignment, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop))
        intro.setTextFormat(Qt.TextFormat.RichText)
        intro.setWordWrap(True)
        layout.addWidget(intro)

        buttons_row = QHBoxLayout()
        self.copilot_overview_button = QPushButton("Open Copilot Assistant")
        self.copilot_overview_button.setMinimumHeight(48)
        self.copilot_overview_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.copilot_overview_button.clicked.connect(lambda: self._focus_module("Copilot Assistant"))
        self._register_button(self.copilot_overview_button)
        buttons_row.addWidget(self.copilot_overview_button, 2)

        self.custom_overview_button = QPushButton("Open Custom Hardening")
        self.custom_overview_button.setMinimumHeight(48)
        self.custom_overview_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.custom_overview_button.clicked.connect(lambda: self._focus_module(self.custom_module_title))
        self._register_button(self.custom_overview_button)
        buttons_row.addWidget(self.custom_overview_button, 2)

        self.preview_remote_button = QPushButton("Preview Remote App Block")
        self.preview_remote_button.clicked.connect(self._show_remote_preview)
        buttons_row.addWidget(self.preview_remote_button, 1)
        buttons_row.addStretch()
        layout.addLayout(buttons_row)

        self.overview_summary = QPlainTextEdit()
        self.overview_summary.setReadOnly(True)
        self.overview_summary.setPlaceholderText("Press Refresh Overview to gather current security insights.")
        layout.addWidget(self.overview_summary, 1)

        refresh_row = QHBoxLayout()
        self.refresh_overview_btn = QPushButton("Refresh Overview")
        self.refresh_overview_btn.clicked.connect(self._update_overview_summary)
        refresh_row.addWidget(self.refresh_overview_btn)
        refresh_row.addStretch()
        layout.addLayout(refresh_row)

        layout.addStretch()
        return widget

    def _build_actions_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        intro = QLabel("Select a module to view focused controls and launch hardening actions without clutter.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        content_layout = QHBoxLayout()
        layout.addLayout(content_layout, 1)

        self.module_list = QListWidget()
        self.module_list.setAlternatingRowColors(True)
        self.module_list.setSelectionMode(QListWidget.SingleSelection)
        self.module_list.setFixedWidth(220)
        content_layout.addWidget(self.module_list)

        self.module_stack = QStackedWidget()
        content_layout.addWidget(self.module_stack, 1)

        modules: List[Tuple[str, str, List[Tuple[str, str, str, Callable[[], Any]]], Optional[Callable[[], QWidget]]]] = [
            (
                "Copilot Assistant",
                "Ask GitHub Copilot CLI questions directly from the console. Set COPILOT_CLI_COMMAND to override the command if needed.",
                [],
                self._build_copilot_panel,
            ),
            (
                self.custom_module_title,
                "Build tailored hardening runs by selecting exactly the checks you want.",
                [],
                self._build_custom_hardening_panel,
            ),
            (
                "SSH Hardening",
                "Lock down OpenSSH with restrictive defaults and safer authentication policies.",
                [("harden_ssh", "Harden SSH", "Apply opinionated OpenSSH lockdown.", partial(harden_ssh, dry_run=False))],
                None,
            ),
            (
                "SMB Hardening",
                "Reconfigure Samba to eliminate insecure shares and unwanted exposure.",
                [("secure_smb", "Harden SMB", "Apply Samba security baseline.", partial(secure_smb, dry_run=False))],
                None,
            ),
            (
                "Core Services",
                "Run the core service hardening checklist to tighten baseline configurations.",
                [
                    (
                        "harden_system",
                        "Harden Core Services",
                        "Run system hardening checklist.",
                        partial(system_hardening_check.apply_full_hardening, dry_run=False),
                    )
                ],
                None,
            ),
            (
                "Remote Desktop",
                "Stop RDP/VNC style services and ensure related ports stay closed.",
                [("disable_rdp", "Disable RDP/VNC", "Stop remote desktop services and deny ports.", partial(disable_rdp_vnc, dry_run=False))],
                None,
            ),
            (
                "Camera Controls",
                "Disconnect local camera hardware and block streaming endpoints.",
                [("disable_cameras", "Disable Cameras", "Disconnect local camera devices.", partial(disable_cameras, dry_run=False))],
                None,
            ),
            (
                "Legacy Servers",
                "Mask or disable unused legacy server daemons to shrink the attack surface.",
                [("disable_servers", "Disable Legacy Servers", "Stop unused network daemons.", partial(disable_servers, dry_run=False))],
                None,
            ),
            (
                "Spying Services",
                "Cut off background services commonly abused for surveillance or data leakage.",
                [("disable_spying", "Disable Spying Services", "Shut down communication services.", partial(disable_spying_services_task, dry_run=False))],
                None,
            ),
            (
                "inetd/xinetd",
                "Disable legacy super-server daemons that should never run on hardened systems.",
                [("harden_inetd", "Harden inetd/xinetd", "Mask legacy super-server daemons.", partial(disable_inetd_services, dry_run=False))],
                None,
            ),
            (
                "Remote Applications",
                "Block remote-access ports and enforce application restrictions.",
                [("harden_remote_apps", "Block Remote Apps", "Reject ports used by remote access tools.", partial(block_remote_apps_task, dry_run=False))],
                None,
            ),
            (
                "Loopback Protection",
                "Prevent localhost abuse by dropping unauthorized loopback traffic.",
                [("harden_loopback", "Block Loopback Traffic", "Drop 127.0.0.0/24 and lo interface flows.", partial(block_loopback_task, dry_run=False))],
                None,
            ),
            (
                "Account Security",
                "Audit and remediate local accounts, groups, and suspicious symlinks.",
                [
                    (
                        "cleanup_accounts",
                        "Cleanup Accounts",
                        "Remove unneeded users/groups and break symlinks.",
                        partial(cleanup_accounts_task, auto_remove=True, break_symlinks=True, dry_run=False),
                    )
                ],
                None,
            ),
            (
                "Rootkit Response",
                "Automatically remediate rootkit scanner alerts and repair known issues.",
                [("remediate_rootkits", "Remediate Rootkit Alerts", "Clean scanner warnings and lock service accounts.", partial(remediate_rootkit_findings, dry_run=False))],
                None,
            ),
            (
                "Firewall",
                "Tighten firewall policies and export current rules for auditing.",
                [("harden_firewall", "Harden Firewall", "Export and tighten firewall policies.", partial(harden_firewall, dry_run=False))],
                None,
            ),
            (
                "Privilege Hygiene",
                "Remove passwordless sudo entries to keep privilege escalation gated.",
                [("remove_nopasswd", "Remove Passwordless sudo", "Require credentials for privileged escalation.", partial(remove_passwordless_sudo, dry_run=False))],
                None,
            ),
            (
                "Security Tooling",
                "Ensure core security utilities are installed and ready for use.",
                [("install_security_tools", "Install Security Tooling", "Install rkhunter, chkrootkit, fail2ban.", partial(install_security_tools, dry_run=False))],
                None,
            ),
            (
                "Diagnostics",
                "Run investigative utilities to capture current system health snapshots.",
                [
                    ("scan_rootkits", "Run Rootkit Scan", "Execute chkrootkit and rkhunter sweeps.", partial(scan_rootkits, dry_run=False)),
                    ("verify_boot", "Verify Boot Partitions", "Inspect MMC boot partitions for tampering.", partial(verify_boot_partitions, dry_run=False)),
                    (
                        "firewall_export",
                        "Export Firewall State",
                        "Produce a firewall ruleset export and summary.",
                        partial(firewall_security.export_firewall_security, dry_run=False),
                    ),
                ],
                None,
            ),
            (
                "VPN Profiles",
                "Manage OpenVPN profiles used by this workstation.",
                [],
                self._build_vpn_group,
            ),
        ]

        for title, description, actions, extra_builder in modules:
            extra_widget = extra_builder() if extra_builder else None
            self._add_module_screen(title, description, actions, extra_widget)

        self.module_list.currentRowChanged.connect(self.module_stack.setCurrentIndex)
        if self.module_list.count():
            self.module_list.setCurrentRow(0)

        layout.addStretch()
        return widget

    def _build_copilot_panel(self) -> QWidget:
        container = QWidget()
        outer_layout = QVBoxLayout()
        container.setLayout(outer_layout)

        intro = QLabel(
            "Send prompts to the Copilot CLI installed on this system.\n"
            "Set the COPILOT_CLI_COMMAND environment variable to override the default command"
            " (default: 'copilot chat')."
        )
        intro.setWordWrap(True)
        outer_layout.addWidget(intro)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        self.copilot_transcript = QPlainTextEdit()
        self.copilot_transcript.setReadOnly(True)
        self.copilot_transcript.setStyleSheet("font-family: monospace;")
        self.copilot_transcript.setPlaceholderText("Copilot responses will appear here.")
        splitter.addWidget(self.copilot_transcript)

        self.copilot_prompt_input = QPlainTextEdit()
        self.copilot_prompt_input.setPlaceholderText("Enter a prompt for GitHub Copilot CLI...")
        self.copilot_prompt_input.setMaximumBlockCount(500)
        splitter.addWidget(self.copilot_prompt_input)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        outer_layout.addWidget(splitter, 1)

        controls = QHBoxLayout()
        send_btn = QPushButton("Send to Copilot")
        send_btn.clicked.connect(self._send_copilot_message)
        self._register_button(send_btn)
        controls.addWidget(send_btn)

        clear_btn = QPushButton("Clear Transcript")
        clear_btn.clicked.connect(self._clear_copilot_transcript)
        self._register_button(clear_btn)
        controls.addWidget(clear_btn)

        controls.addStretch()
        outer_layout.addLayout(controls)

        self.task_titles[self.copilot_task_id] = "Copilot Assistant Request"

        return container

    def _build_vpn_group(self) -> QGroupBox:
        group = QGroupBox("VPN Profile Management")
        layout = QGridLayout()
        group.setLayout(layout)

        row = 0

        layout.addWidget(QLabel("Profile"), row, 0)
        self.vpn_profile_combo = QComboBox()
        self.vpn_profile_combo.setEditable(False)
        self.vpn_profile_combo.setToolTip("Available VPN profiles loaded from the workspace")
        self.vpn_profile_combo.currentTextChanged.connect(self._vpn_selection_changed)
        layout.addWidget(self.vpn_profile_combo, row, 1, 1, 3)

        row += 1
        btn_add = QPushButton("Add Profile")
        btn_add.clicked.connect(self._vpn_add)
        self._register_button(btn_add)
        layout.addWidget(btn_add, row, 0)

        btn_remove = QPushButton("Remove Profile")
        btn_remove.clicked.connect(self._vpn_remove)
        self._register_button(btn_remove)
        layout.addWidget(btn_remove, row, 1)

        btn_clone = QPushButton("Clone")
        btn_clone.clicked.connect(self._vpn_clone)
        self._register_button(btn_clone)
        layout.addWidget(btn_clone, row, 2)

        btn_configure = QPushButton("Configure")
        btn_configure.clicked.connect(self._vpn_configure)
        self._register_button(btn_configure)
        layout.addWidget(btn_configure, row, 3)

        row += 1
        layout.addWidget(QLabel("Config Path"), row, 0)
        self.vpn_profile_path = QLineEdit()
        self.vpn_profile_path.setPlaceholderText("/etc/openvpn/client/profile.ovpn")
        layout.addWidget(self.vpn_profile_path, row, 1, 1, 3)

        row += 1
        btn_export = QPushButton("Export")
        btn_export.clicked.connect(self._vpn_export)
        self._register_button(btn_export)
        layout.addWidget(btn_export, row, 0)

        btn_import = QPushButton("Import from Path")
        btn_import.clicked.connect(self._vpn_import)
        self._register_button(btn_import)
        layout.addWidget(btn_import, row, 1)

        row += 1
        layout.addWidget(QLabel("Username"), row, 0)
        self.vpn_username_input = QLineEdit()
        layout.addWidget(self.vpn_username_input, row, 1, 1, 3)

        row += 1
        layout.addWidget(QLabel("Password"), row, 0)
        self.vpn_password_input = QLineEdit()
        self.vpn_password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.vpn_password_input, row, 1, 1, 3)

        row += 1
        self.vpn_remember_checkbox = QCheckBox("Remember credentials (encrypted)")
        layout.addWidget(self.vpn_remember_checkbox, row, 0, 1, 2)
        self.vpn_save_credentials_btn = QPushButton("Save Credentials")
        self.vpn_save_credentials_btn.clicked.connect(self._vpn_save_credentials)
        self._register_button(self.vpn_save_credentials_btn)
        layout.addWidget(self.vpn_save_credentials_btn, row, 2, 1, 2)

        row += 1
        self.vpn_connect_btn = QPushButton("Connect")
        self.vpn_connect_btn.clicked.connect(self._vpn_connect)
        self._register_button(self.vpn_connect_btn)
        layout.addWidget(self.vpn_connect_btn, row, 0, 1, 2)

        self.vpn_disconnect_btn = QPushButton("Disconnect")
        self.vpn_disconnect_btn.clicked.connect(self._vpn_disconnect)
        self._register_button(self.vpn_disconnect_btn)
        layout.addWidget(self.vpn_disconnect_btn, row, 2, 1, 2)

        row += 1
        self.vpn_status_label = QLabel("VPN status: disconnected")
        self.vpn_status_label.setWordWrap(True)
        layout.addWidget(self.vpn_status_label, row, 0, 1, 4)

        layout.setColumnStretch(1, 1)
        layout.setColumnStretch(2, 1)

        return group

    def _build_copilot_command(self, prompt: str) -> List[str]:
        command_spec = (self.copilot_cli_command or "").strip()
        if not command_spec:
            command_spec = "copilot chat"

        parts = shlex.split(command_spec)
        if not parts:
            parts = ["copilot", "chat"]

        # Allow users to provide a {prompt} placeholder.
        replaced = False
        resolved: List[str] = []
        for part in parts:
            if part == "{prompt}":
                resolved.append(prompt)
                replaced = True
            else:
                resolved.append(part)

        if replaced:
            return resolved

        return resolved + [prompt]

    def _run_copilot_cli(self, prompt: str) -> Dict[str, Any]:
        cmd = self._build_copilot_command(prompt)
        command_display = " ".join(shlex.quote(arg) for arg in cmd)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=180,
            )
        except FileNotFoundError:
            return {
                "success": False,
                "message": f"Copilot CLI not found when running: {command_display}",
                "details": {"command": command_display},
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "message": "Copilot CLI timed out after 180 seconds.",
                "details": {"command": command_display},
            }
        except Exception as exc:
            return {
                "success": False,
                "message": f"Copilot CLI failed: {exc}",
                "details": {"command": command_display},
            }

        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        success = result.returncode == 0

        if success:
            message = stdout if stdout else "Copilot responded with no content."
            if stderr:
                message += f" (stderr: {stderr})"
        else:
            message = "Copilot CLI failed"
            if stderr:
                message += f": {stderr}"
            elif stdout:
                message += f": {stdout}"
            else:
                message += "."

        return {
            "success": success,
            "message": message,
            "details": {
                "stdout": stdout,
                "stderr": stderr,
                "returncode": result.returncode,
                "command": command_display,
            },
            "stdout": stdout,
            "stderr": stderr,
            "command": command_display,
        }

    def _send_copilot_message(self) -> None:
        if self.copilot_prompt_input is None:
            return
        prompt = self.copilot_prompt_input.toPlainText().strip()
        if not prompt:
            self.append_log("Copilot prompt is empty.", "error")
            return

        self.copilot_pending_prompt = prompt
        self.append_log(f"Sending prompt to Copilot: {prompt}", "task")
        task = partial(self._run_copilot_cli, prompt)
        self._start_task(self.copilot_task_id, "Copilot Assistant Request", task)

    def _clear_copilot_transcript(self) -> None:
        if self.copilot_transcript is not None:
            self.copilot_transcript.clear()
        if self.copilot_prompt_input is not None:
            self.copilot_prompt_input.clear()

    def _handle_copilot_result(self, result: Any) -> None:
        prompt = self.copilot_pending_prompt or ""
        self.copilot_pending_prompt = None
        self._update_copilot_transcript(prompt, result)

    def _update_copilot_transcript(self, prompt: str, result: Any) -> None:
        if self.copilot_transcript is None:
            return

        if isinstance(result, dict):
            response = str(result.get("stdout", "") or "").strip()
            if not response:
                response = str(result.get("message", "")).strip()
            stderr_text = str(result.get("stderr", "") or "").strip()
        else:
            response = str(result)
            stderr_text = ""

        lines: List[str] = []
        if prompt:
            lines.append(f"➡ Prompt:\n{prompt}")
        if response:
            lines.append(f"⬅ Response:\n{response}")
        if stderr_text:
            lines.append(f"⚠ stderr:\n{stderr_text}")
        if not lines:
            lines.append("(No output received from Copilot CLI)")

        self.copilot_transcript.appendPlainText("\n".join(lines))
        scrollbar = self.copilot_transcript.verticalScrollBar()
        if scrollbar is not None:
            scrollbar.setValue(scrollbar.maximum())

        if self.copilot_prompt_input is not None:
            self.copilot_prompt_input.clear()

    def _add_module_screen(
        self,
        title: str,
        description: str,
        actions: List[Tuple[str, str, str, Callable[[], Any]]],
        extra_widget: Optional[QWidget] = None,
    ) -> None:
        item = QListWidgetItem(title)
        size = item.sizeHint()
        size.setHeight(max(size.height(), 32))
        item.setSizeHint(size)
        self.module_list.addItem(item)
        screen = self._create_module_screen(description, actions, extra_widget)
        self.module_stack.addWidget(screen)
        self.module_indices[title] = self.module_stack.count() - 1

    def _create_module_screen(
        self,
        description: str,
        actions: List[Tuple[str, str, str, Callable[[], Any]]],
        extra_widget: Optional[QWidget] = None,
    ) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout()
        container.setLayout(layout)

        if description:
            desc_label = QLabel(description)
            desc_label.setWordWrap(True)
            layout.addWidget(desc_label)

        for task_id, label_text, tooltip, func in actions:
            button = QPushButton(label_text)
            button.setToolTip(tooltip)
            button.setMinimumHeight(44)
            button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            button.clicked.connect(partial(self._start_task, task_id, label_text, func))
            self.task_titles[task_id] = label_text
            self._register_button(button)
            layout.addWidget(button)

        if extra_widget is not None:
            layout.addWidget(extra_widget)

        layout.addStretch()
        return container

    def _focus_module(self, title: str) -> None:
        index = self.module_indices.get(title)
        if index is None:
            return
        if self.actions_tab_index is not None:
            self.tabs.setCurrentIndex(self.actions_tab_index)
        if index != self.module_list.currentRow():
            self.module_list.setCurrentRow(index)
        self.module_stack.setCurrentIndex(index)

    def _build_custom_hardening_panel(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout()
        container.setLayout(layout)

        help_text = QLabel(
            "Select one or more tasks to build a custom run. Use dry-run mode to preview commands "
            "before applying changes."
        )
        help_text.setWordWrap(True)
        layout.addWidget(help_text)

        self.custom_select_all = QCheckBox("Select all tasks")
        self.custom_select_all.toggled.connect(self._on_custom_select_all_toggled)
        layout.addWidget(self.custom_select_all)

        self.custom_task_list = QListWidget()
        self.custom_task_list.setAlternatingRowColors(True)
        self.custom_task_list.itemChanged.connect(self._on_custom_item_changed)
        layout.addWidget(self.custom_task_list, 1)
        self._populate_custom_task_list()

        controls_row = QHBoxLayout()
        self.custom_dry_run_checkbox = QCheckBox("Dry run")
        controls_row.addWidget(self.custom_dry_run_checkbox)

        run_button = QPushButton("Run Selection")
        run_button.clicked.connect(self._trigger_custom_hardening)
        self._register_button(run_button)
        controls_row.addWidget(run_button)

        clear_button = QPushButton("Clear Selection")
        clear_button.clicked.connect(self._clear_custom_selection)
        self._register_button(clear_button)
        controls_row.addWidget(clear_button)
        controls_row.addStretch()
        layout.addLayout(controls_row)

        self.custom_output = QPlainTextEdit()
        self.custom_output.setReadOnly(True)
        self.custom_output.setPlaceholderText("Custom hardening results will appear here.")
        layout.addWidget(self.custom_output, 1)

        self.task_titles[self.custom_task_id] = "Custom Hardening Run"

        return container

    def _populate_custom_task_list(self) -> None:
        if self.custom_task_list is None:
            return
        self.custom_task_list.blockSignals(True)
        self.custom_task_list.clear()
        for task in custom_hardening.get_available_tasks():
            item = QListWidgetItem(f"{task.name} ({task.key})")
            item.setToolTip(task.description)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, task.key)
            self.custom_task_list.addItem(item)
        self.custom_task_list.blockSignals(False)
        if self.custom_select_all is not None:
            self.custom_select_all.blockSignals(True)
            self.custom_select_all.setChecked(False)
            self.custom_select_all.blockSignals(False)

    def _collect_custom_task_keys(self) -> List[str]:
        keys: List[str] = []
        if self.custom_task_list is None:
            return keys
        for index in range(self.custom_task_list.count()):
            item = self.custom_task_list.item(index)
            if item is None:
                continue
            if item.checkState() == Qt.CheckState.Checked:
                key = item.data(Qt.ItemDataRole.UserRole)
                if key:
                    keys.append(str(key))
        return keys

    def _trigger_custom_hardening(self) -> None:
        keys = self._collect_custom_task_keys()
        if not keys:
            QMessageBox.information(self, "Custom Hardening", "Select at least one task to run.")
            return
        dry_run = bool(self.custom_dry_run_checkbox is not None and self.custom_dry_run_checkbox.isChecked())
        self.pending_custom_selection = {"keys": keys, "dry_run": dry_run}
        preview_lines = [
            "Launching custom hardening...",
            "Mode: dry-run" if dry_run else "Mode: live",
            "Selected: " + ", ".join(keys),
        ]
        if self.custom_output is not None:
            self.custom_output.setPlainText("\n".join(preview_lines))
        summary = ", ".join(keys)
        self.append_log(
            f"Queued custom hardening with {len(keys)} task(s): {summary}",
            "task",
        )
        func = partial(custom_hardening.run_custom_hardening, keys, dry_run=dry_run)
        self._start_task(self.custom_task_id, "Custom Hardening Run", func)

    def _clear_custom_selection(self) -> None:
        if self.custom_task_list is None:
            return
        self.custom_task_list.blockSignals(True)
        for index in range(self.custom_task_list.count()):
            item = self.custom_task_list.item(index)
            if item is not None:
                item.setCheckState(Qt.CheckState.Unchecked)
        self.custom_task_list.blockSignals(False)
        if self.custom_select_all is not None:
            self.custom_select_all.blockSignals(True)
            self.custom_select_all.setChecked(False)
            self.custom_select_all.blockSignals(False)

    def _on_custom_select_all_toggled(self, checked: bool) -> None:
        if self.custom_task_list is None:
            return
        self.custom_task_list.blockSignals(True)
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for index in range(self.custom_task_list.count()):
            item = self.custom_task_list.item(index)
            if item is not None:
                item.setCheckState(state)
        self.custom_task_list.blockSignals(False)

    def _on_custom_item_changed(self, item: QListWidgetItem) -> None:
        if self.custom_task_list is None or self.custom_select_all is None:
            return
        total = self.custom_task_list.count()
        checked = 0
        for idx in range(total):
            entry = self.custom_task_list.item(idx)
            if entry is not None and entry.checkState() == Qt.CheckState.Checked:
                checked += 1
        self.custom_select_all.blockSignals(True)
        self.custom_select_all.setChecked(checked == total and total > 0)
        self.custom_select_all.blockSignals(False)

    def _update_custom_output(self, payload: Any) -> None:
        if self.custom_output is None:
            return
        if isinstance(payload, dict):
            lines = [f"Success: {payload.get('success')}"]
            selected = payload.get("selected") or []
            if selected:
                lines.append("Selected: " + ", ".join(selected))
            missing = payload.get("missing") or []
            if missing:
                lines.append("Missing: " + ", ".join(missing))
            for entry in payload.get("results", []):
                name = entry.get("name", entry.get("key", "task"))
                status = "OK" if entry.get("success") else "FAIL"
                message = entry.get("message", "")
                lines.append(f"[{status}] {name}: {message}")
            message = payload.get("message")
            if message:
                lines.append(message)
            self.custom_output.setPlainText("\n".join(lines))
        else:
            self.custom_output.setPlainText(str(payload))
    def _build_summaries_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        self.summary_combo = QComboBox()
        self.summary_sources = [
            ("Integrated Security", integrated_security.get_integrated_security_summary),
            ("SSH Hardening", ssh_hardening_check.get_ssh_hardening_summary),
            ("SMB Hardening", smb_hardening_check.get_smb_security_summary),
            ("System Hardening", system_hardening_check.get_system_hardening_summary),
            ("Anti-Spying", anti_spying_check.get_anti_spying_summary),
            ("inetd/xinetd", inetd_check.get_inetd_summary),
            ("Remote Applications", block_remote_module.get_remote_app_summary),
            ("Loopback Restriction", loopback_restriction.get_loopback_summary),
            ("Account Security", account_security.get_account_security_summary),
            ("Rootkit Remediation", rootkit_remediation.get_rootkit_remediation_summary),
            ("Firewall", firewall_security.get_firewall_summary),
            ("Firewall Tooling", firewall_installation.get_firewall_installation_summary),
        ]
        for label, func in self.summary_sources:
            self.summary_combo.addItem(label, func)
        layout.addWidget(self.summary_combo)

        refresh_row = QHBoxLayout()
        self.summary_refresh_btn = QPushButton("Load Summary")
        self.summary_refresh_btn.clicked.connect(self._refresh_summary)
        refresh_row.addWidget(self.summary_refresh_btn)
        refresh_row.addStretch()
        layout.addLayout(refresh_row)

        self.summary_output = QPlainTextEdit()
        self.summary_output.setReadOnly(True)
        self.summary_output.setStyleSheet("font-family: monospace;")
        self.summary_output.setPlaceholderText("Load a summary to review the latest scan results.")
        layout.addWidget(self.summary_output, 1)

        layout.addStretch()
        return widget

    def _build_console_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet("background-color: #0c0c0c; color: #e0e0e0; font-family: monospace;")
        layout.addWidget(self.console_output, 1)

        console_row = QHBoxLayout()
        self.console_input = QLineEdit()
        self.console_input.setPlaceholderText("Type a command (e.g., harden_ssh, firewall_summary, help)...")
        self.console_input.returnPressed.connect(self._handle_console_command)
        console_row.addWidget(self.console_input)

        self.console_send_btn = QPushButton("Send Command")
        self.console_send_btn.clicked.connect(self._handle_console_command)
        console_row.addWidget(self.console_send_btn)
        layout.addLayout(console_row)

        return widget

    def _register_button(self, button: QPushButton) -> None:
        self.buttons.append(button)

    def append_log(self, text: str, level: str = "info") -> None:
        colors = {
            "info": "#cfd8dc",
            "task": "#82aaff",
            "success": "#4caf50",
            "error": "#ff5370",
        }
        safe = html.escape(text).replace("\n", "<br>")
        color = colors.get(level, colors["info"])
        self.log_view.append(f"<span style='color:{color};'>{safe}</span>")
        scrollbar = self.log_view.verticalScrollBar()
        if scrollbar:
            scrollbar.setValue(scrollbar.maximum())

    def _set_busy(self, busy: bool) -> None:
        for button in self.buttons:
            button.setEnabled(not busy)
        self.console_input.setEnabled(not busy)
        self.console_send_btn.setEnabled(not busy)
        if self.vpn_profile_combo is not None:
            self.vpn_profile_combo.setEnabled(not busy)
        if self.copilot_prompt_input is not None:
            self.copilot_prompt_input.setEnabled(not busy)

    def _update_runtime_summary(
        self,
        *,
        running: bool = False,
        running_title: Optional[str] = None,
        last_message: Optional[str] = None,
    ) -> None:
        if last_message is not None:
            self.last_status_message = last_message

        if self.total_tasks_run:
            summary = (
                "Runtime Summary: "
                f"{self.successful_tasks} success, {self.failed_tasks} failed "
                f"({self.total_tasks_run} total). Last task: {self.last_task_title}."
            )
            if not running and self.last_status_message:
                summary += f" Last result: {self.last_status_message}"
        else:
            summary = "Runtime Summary: Ready. No tasks run yet."

        if running and running_title:
            summary += f" Running: {running_title}..."

        self.status_label.setText(summary)

    def _record_task_outcome(self, title: str, success: bool, message: str) -> None:
        self.total_tasks_run += 1
        if success:
            self.successful_tasks += 1
        else:
            self.failed_tasks += 1

        self.last_task_title = title
        fallback = "Task completed successfully." if success else "Task encountered issues."
        final_message = message or fallback
        self.current_task_title = None
        self._update_runtime_summary(last_message=final_message)

        archived_path = self._auto_archive_session_log()
        if archived_path is not None:
            self.append_log(f"Session log archived to {archived_path}", "task")

    def _start_task(self, task_id: str, title: str, func: Callable) -> None:
        if self.current_thread is not None:
            running = self.task_titles.get(self.current_task_id or "", "Current task")
            self.append_log(f"Cannot start '{title}'. '{running}' is still running.", "error")
            return

        self.current_task_title = title
        self._update_runtime_summary(running=True, running_title=title)
        self.append_log(f"Starting {title}...", "task")

        self._set_busy(True)
        self.current_task_id = task_id
        runner = TaskRunner(task_id, func)
        self.current_thread = runner
        runner.completed.connect(self._task_completed)
        runner.failed.connect(self._task_failed)
        runner.finished.connect(self._task_finished)
        runner.start()

    def _task_completed(self, task_id: str, result: Any) -> None:
        title = self.task_titles.get(task_id, task_id)
        info = self._normalize_result(result)
        success_flag = info["success"]
        success = True if success_flag is None else bool(success_flag)
        status = "SUCCESS" if success else "FAILED"
        level = "success" if success else "error"
        message = info["message"] or "Task finished."
        self.append_log(f"{title}: {status} - {message}", level)

        if info.get("report"):
            self.append_log(info["report"], "task")

        details = info.get("details")
        if details:
            rendered = pprint.pformat(details, compact=False)
            self.append_log(rendered, "task")

        if task_id == self.copilot_task_id:
            self._handle_copilot_result(result)

        self._record_task_outcome(title, success, message)
        if task_id == self.custom_task_id:
            self._update_custom_output(result)
            self.pending_custom_selection = None

    def _task_failed(self, task_id: str, message: str) -> None:
        title = self.task_titles.get(task_id, task_id)
        failure_message = message or "Task encountered an unexpected error."
        self.append_log(f"{title}: ERROR - {failure_message}", "error")
        self._record_task_outcome(title, False, failure_message)
        if task_id == self.custom_task_id:
            self._update_custom_output({"success": False, "message": failure_message})
            self.pending_custom_selection = None

    def _task_finished(self) -> None:
        self._set_busy(False)
        if self.current_thread is not None:
            self.current_thread.deleteLater()
        self.current_thread = None
        self.current_task_id = None
        self._update_runtime_summary()

    def _normalize_result(self, result: Any) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "success": None,
            "message": "",
            "details": None,
            "report": None,
        }

        if isinstance(result, dict):
            info["success"] = result.get("success")
            info["message"] = str(result.get("message", ""))
            if "details" in result:
                info["details"] = result["details"]
            elif "results" in result:
                info["details"] = result["results"]
            if "report" in result:
                info["report"] = result["report"]
        elif isinstance(result, (list, tuple)):
            if result:
                info["success"] = bool(result[0])
            if len(result) > 1:
                info["message"] = str(result[1])
            if len(result) > 2:
                info["details"] = list(result[2:])
        elif isinstance(result, str):
            info["message"] = result
        else:
            info["message"] = repr(result)

        return info

    def _save_session_log(self) -> Optional[str]:
        default_path = Path.home() / "flatline_dixie_session.log"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Session Log",
            str(default_path),
            "Text Files (*.txt);;All Files (*)",
        )
        if not file_path:
            return None
        try:
            with open(file_path, "w", encoding="utf-8") as handle:
                handle.write(self.log_view.toPlainText())
        except Exception as exc:  # pragma: no cover - GUI prompt
            QMessageBox.critical(self, "Save Error", f"Could not save the session log:\n{exc}")
            return None

        self.append_log(f"Session log saved to {file_path}", "success")
        return file_path

    def _auto_archive_session_log(self) -> Optional[Path]:
        logs_dir = Path.home() / "flatline_dixie_logs"
        try:
            logs_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = logs_dir / f"session_{timestamp}.log"
            with open(file_path, "w", encoding="utf-8") as handle:
                handle.write(self.log_view.toPlainText())
        except Exception as exc:  # pragma: no cover - best effort archive
            self.append_log(f"Unable to archive session log automatically: {exc}", "error")
            return None

        return file_path

    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:  # pragma: no cover - GUI lifecycle
        event = a0
        if event is None:
            return
        prompt = QMessageBox(self)
        prompt.setWindowTitle("Save Session?")
        prompt.setIcon(QMessageBox.Question)
        prompt.setText("Would you like to save the session log before exiting?")
        prompt.setStandardButtons(QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
        response = prompt.exec()

        if response == QMessageBox.Cancel:
            event.ignore()
            return

        if response == QMessageBox.Yes:
            try:
                saved_path = self._save_session_log()
            except Exception as exc:
                QMessageBox.warning(self, "Save Failed", f"Failed to save session: {exc}")
                event.ignore()
                return
            if not saved_path:
                event.ignore()
                return
            QMessageBox.information(self, "Session Saved", f"Session log saved to:\n{saved_path}")

        if self.vpn_process:
            vpn_prompt = QMessageBox(self)
            vpn_prompt.setWindowTitle("VPN Connection Active")
            vpn_prompt.setIcon(QMessageBox.Question)
            vpn_prompt.setText(
                "An OpenVPN connection is still active. You can keep the tunnel running after the GUI closes."
            )
            keep_button = vpn_prompt.addButton("Keep Running", QMessageBox.YesRole)
            disconnect_button = vpn_prompt.addButton("Disconnect", QMessageBox.NoRole)
            cancel_button = vpn_prompt.addButton("Cancel", QMessageBox.RejectRole)
            vpn_prompt.setDefaultButton(keep_button)  # type: ignore[arg-type]
            vpn_prompt.exec()
            clicked = vpn_prompt.clickedButton()
            if clicked is cancel_button:
                event.ignore()
                return
            if clicked is disconnect_button:
                self._vpn_disconnect()
                try:
                    if self.vpn_process:
                        self.vpn_process.wait(timeout=3)
                except Exception:
                    pass
                self._cleanup_vpn_temp_files()
                self.vpn_process = None
                self.vpn_connected_profile = None
            else:
                self.append_log("GUI closed while VPN connection continues in background.", "task")
                self._cleanup_vpn_temp_files()
                self.vpn_process = None
                self.vpn_connected_profile = None

        if self.vpn_status_timer.isActive():
            self.vpn_status_timer.stop()

        event.accept()

    def _update_overview_summary(self) -> None:
        snapshots: List[str] = []

        def add_snapshot(label: str, producer: Callable) -> None:
            try:
                outcome = producer()
                if isinstance(outcome, tuple) and len(outcome) >= 2:
                    ok, message = outcome[0], outcome[1]
                    status = "OK" if ok else "ISSUES"
                    snapshots.append(f"{label}: {status}")
                    snapshots.append(message.splitlines()[0])
                elif isinstance(outcome, str):
                    snapshots.append(f"{label}: {outcome}")
                else:
                    snapshots.append(f"{label}: {outcome}")
            except Exception as exc:
                snapshots.append(f"{label}: error - {exc}")

        add_snapshot("SSH", ssh_hardening_check.verify_ssh_hardening)
        add_snapshot("SMB", smb_hardening_check.verify_smb_security)
        add_snapshot("System", system_hardening_check.verify_system_hardening)

        try:
            snapshots.append(block_remote_module.get_remote_app_summary())
        except Exception as exc:
            snapshots.append(f"Remote Applications: error - {exc}")

        try:
            snapshots.append(loopback_restriction.get_loopback_summary())
        except Exception as exc:
            snapshots.append(f"Loopback: error - {exc}")

        try:
            account_overview = account_security.get_account_security_summary().splitlines()[0]
            snapshots.append(account_overview)
        except Exception as exc:
            snapshots.append(f"Account Security: error - {exc}")

        try:
            rootkit_overview = rootkit_remediation.get_rootkit_remediation_summary().splitlines()[0]
            snapshots.append(rootkit_overview)
        except Exception as exc:
            snapshots.append(f"Rootkit Remediation: error - {exc}")

        try:
            snapshots.append(firewall_security.get_firewall_summary())
        except Exception as exc:
            snapshots.append(f"Firewall: error - {exc}")

        self.overview_summary.setPlainText("\n".join(snapshots))

    def _show_remote_preview(self) -> None:
        try:
            preview = block_remote_module.preview_remote_app_block()
            self.overview_summary.setPlainText(preview)
            self.append_log("Generated remote application block preview.")
        except Exception as exc:
            self.append_log(f"Unable to build preview: {exc}", "error")

    def _refresh_summary(self) -> None:
        if not hasattr(self, "summary_combo"):
            return
        func = self.summary_combo.currentData()
        if not callable(func):
            return
        try:
            text = func()
        except Exception as exc:
            text = f"Summary retrieval failed: {exc}"
        self.summary_output.setPlainText(str(text) if text is not None else "")
        self._load_vpn_profiles()

    def _handle_console_command(self) -> None:
        user_text = self.console_input.text().strip()
        if not user_text:
            return
        self.console_input.clear()
        self._append_console_line("[You]", user_text, "#82aaff")
        try:
            response = chat.handle_input(user_text)
        except Exception as exc:  # pragma: no cover - defensive guard
            response = f"Error: {exc}"
        self._append_console_line("[Dixie]", response, "#c3e88d")

    def _append_console_line(self, prefix: str, text: str, color: str) -> None:
        safe = html.escape(text).replace("\n", "<br>")
        self.console_output.append(f"<span style='color:{color};'>{prefix} {safe}</span>")
        scrollbar = self.console_output.verticalScrollBar()
        if scrollbar:
            scrollbar.setValue(scrollbar.maximum())

    # VPN management helpers -------------------------------------------------

    def _load_vpn_profiles(self) -> None:
        raw: Dict[str, Any] = {}
        try:
            if os.path.exists(self.vpn_store_path):
                with open(self.vpn_store_path, "r", encoding="utf-8") as handle:
                    raw = json.load(handle)
        except Exception as exc:
            self.append_log(f"Failed to load VPN profiles: {exc}", "error")
        self.vpn_profiles = {
            name: self._normalize_vpn_profile(payload) for name, payload in raw.items()
        }

        if self.vpn_profile_combo is None:
            return

        current = self.vpn_profile_combo.currentText()
        self.vpn_profile_combo.blockSignals(True)
        self.vpn_profile_combo.clear()
        for name in sorted(self.vpn_profiles.keys()):
            self.vpn_profile_combo.addItem(name)
        selected_name = ""
        if current and current in self.vpn_profiles:
            selected_name = current
        elif self.vpn_profiles:
            selected_name = sorted(self.vpn_profiles.keys())[0]
        if selected_name:
            idx = self.vpn_profile_combo.findText(selected_name)
            if idx >= 0:
                self.vpn_profile_combo.setCurrentIndex(idx)
        self.vpn_profile_combo.blockSignals(False)
        self._vpn_selection_changed(self.vpn_profile_combo.currentText())

    def _save_vpn_profiles(self) -> None:
        try:
            with open(self.vpn_store_path, "w", encoding="utf-8") as handle:
                json.dump(self._serialize_vpn_profiles(), handle, indent=2, sort_keys=True)
        except Exception as exc:
            self.append_log(f"Failed to save VPN profiles: {exc}", "error")

    def _normalize_vpn_profile(self, payload: Any) -> Dict[str, str]:
        if isinstance(payload, str):
            return {"path": payload, "username": "", "password": ""}
        if isinstance(payload, dict):
            return {
                "path": str(payload.get("path", "")),
                "username": str(payload.get("username", "")),
                "password": str(payload.get("password", "")),
            }
        return {"path": "", "username": "", "password": ""}

    def _serialize_vpn_profiles(self) -> Dict[str, Dict[str, str]]:
        data: Dict[str, Dict[str, str]] = {}
        for name, profile in self.vpn_profiles.items():
            data[name] = {
                "path": profile.get("path", ""),
                "username": profile.get("username", ""),
                "password": profile.get("password", ""),
            }
        return data

    def _vpn_add(self) -> None:
        name, ok = self._prompt_text("Add VPN Profile", "Profile name:")
        if not ok or not name:
            return
        name = name.strip()
        if name in self.vpn_profiles:
            self._show_message("VPN profile already exists.", QMessageBox.Warning)
            return
        path = self.vpn_profile_path.text().strip() if self.vpn_profile_path is not None else ""
        if not path:
            self._show_message("Provide a configuration path before adding a profile.", QMessageBox.Warning)
            return
        if not os.path.exists(path):
            self._show_message("Warning: specified configuration file does not exist.", QMessageBox.Warning)
        self.vpn_profiles[name] = {"path": path, "username": "", "password": ""}
        self._save_vpn_profiles()
        self._load_vpn_profiles()
        self.append_log(f"VPN profile '{name}' added.", "task")

    def _vpn_remove(self) -> None:
        name = self._vpn_current_profile_name()
        if not name:
            self._show_message("No VPN profile selected to remove.", QMessageBox.Warning)
            return
        self.vpn_profiles.pop(name, None)
        self._save_vpn_profiles()
        self._load_vpn_profiles()
        self.append_log(f"VPN profile '{name}' removed.", "task")

    def _vpn_clone(self) -> None:
        name = self._vpn_current_profile_name()
        if not name:
            self._show_message("Select a VPN profile to clone.", QMessageBox.Warning)
            return
        profile = self.vpn_profiles.get(name)
        if not profile:
            self._show_message("Selected VPN profile has no configuration path.", QMessageBox.Warning)
            return
        new_name, ok = self._prompt_text("Clone VPN Profile", "New profile name:", f"{name}_copy")
        if not ok or not new_name:
            return
        new_name = new_name.strip()
        if new_name in self.vpn_profiles:
            self._show_message("A VPN profile with this name already exists.", QMessageBox.Warning)
            return
        self.vpn_profiles[new_name] = dict(profile)
        self._save_vpn_profiles()
        self._load_vpn_profiles()
        self.append_log(f"VPN profile '{name}' cloned to '{new_name}'.", "task")

    def _vpn_configure(self) -> None:
        name = self._vpn_current_profile_name()
        if not name:
            self._show_message("Select a VPN profile to configure.", QMessageBox.Warning)
            return
        profile = self.vpn_profiles.get(name, {"path": ""})
        existing = profile.get("path", "")
        new_path, ok = self._prompt_text("Configure VPN Profile", "Profile configuration path:", existing)
        if not ok or not new_path:
            return
        profile["path"] = new_path.strip()
        self.vpn_profiles[name] = profile
        if self.vpn_profile_path is not None:
            self.vpn_profile_path.setText(profile["path"])
        self._save_vpn_profiles()
        self._load_vpn_profiles()
        self.append_log(f"VPN profile '{name}' updated.", "task")

    def _vpn_import(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select VPN profile to import",
            os.getcwd(),
            "VPN Profiles (*.ovpn *.conf);;All Files (*)",
        )
        if not file_path:
            return
        name = os.path.splitext(os.path.basename(file_path))[0]
        self.vpn_profiles[name] = {"path": file_path, "username": "", "password": ""}
        if self.vpn_profile_path is not None:
            self.vpn_profile_path.setText(file_path)
        self._save_vpn_profiles()
        self._load_vpn_profiles()
        self.append_log(f"Imported VPN profile '{name}' from {file_path}.", "task")

    def _vpn_export(self) -> None:
        name = self._vpn_current_profile_name()
        if not name:
            self._show_message("Select a VPN profile to export.", QMessageBox.Warning)
            return
        profile = self.vpn_profiles.get(name, {})
        source = profile.get("path")
        if not source or not os.path.exists(source):
            self._show_message("Configured VPN file is missing on disk.", QMessageBox.Warning)
            return
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Export VPN profile",
            os.path.join(os.getcwd(), f"{name}.ovpn"),
            "VPN Profiles (*.ovpn *.conf);;All Files (*)",
        )
        if not destination:
            return
        try:
            self._copy_file(source, destination)
            self.append_log(f"VPN profile '{name}' exported to {destination}.", "success")
        except Exception as exc:
            self.append_log(f"Failed to export profile: {exc}", "error")

    def _vpn_selection_changed(self, name: str) -> None:
        profile = self.vpn_profiles.get(name) if name else None
        path = profile.get("path", "") if profile else ""
        if self.vpn_profile_path is not None:
            self.vpn_profile_path.setText(path)
        stored_user, stored_pass = self._get_stored_credentials(profile)
        if self.vpn_username_input is not None:
            self.vpn_username_input.blockSignals(True)
            self.vpn_username_input.setText(stored_user)
            self.vpn_username_input.blockSignals(False)
        if self.vpn_password_input is not None:
            self.vpn_password_input.clear()
            placeholder = "(stored)" if stored_pass else ""
            self.vpn_password_input.setPlaceholderText(placeholder)
        if self.vpn_remember_checkbox is not None:
            self.vpn_remember_checkbox.blockSignals(True)
            self.vpn_remember_checkbox.setChecked(bool(stored_user or stored_pass))
            self.vpn_remember_checkbox.blockSignals(False)
        self._update_vpn_status("Connected" if self.vpn_process else "Disconnected", connected=bool(self.vpn_process))

    def _vpn_current_profile_name(self) -> str:
        if self.vpn_profile_combo is None:
            return ""
        return self.vpn_profile_combo.currentText().strip()

    def _get_stored_credentials(self, profile: Optional[Dict[str, str]]) -> Tuple[str, str]:
        if not profile:
            return "", ""
        username_token = profile.get("username", "")
        password_token = profile.get("password", "")
        try:
            username = self.vpn_cipher.decrypt(username_token) if username_token else ""
            password = self.vpn_cipher.decrypt(password_token) if password_token else ""
        except Exception as exc:
            self.append_log(f"Unable to decrypt stored VPN credentials: {exc}", "error")
            return "", ""
        return username, password

    def _update_profile_credentials(self, name: str, username: str, password: str, remember: bool) -> None:
        profile = self.vpn_profiles.setdefault(name, {"path": "", "username": "", "password": ""})
        if remember and (username or password):
            profile["username"] = self.vpn_cipher.encrypt(username)
            profile["password"] = self.vpn_cipher.encrypt(password)
        else:
            profile["username"] = ""
            profile["password"] = ""
        self.vpn_profiles[name] = profile
        self._save_vpn_profiles()

    def _update_vpn_status(self, message: str, *, connected: bool) -> None:
        if self.vpn_status_label is not None:
            self.vpn_status_label.setText(f"VPN status: {message}")
        if self.vpn_connect_btn is not None:
            self.vpn_connect_btn.setEnabled(not connected)
        if self.vpn_disconnect_btn is not None:
            self.vpn_disconnect_btn.setEnabled(connected)

    def _vpn_save_credentials(self) -> None:
        name = self._vpn_current_profile_name()
        if not name:
            self._show_message("Select a VPN profile before saving credentials.", QMessageBox.Warning)
            return
        username = self.vpn_username_input.text().strip() if self.vpn_username_input is not None else ""
        password = self.vpn_password_input.text() if self.vpn_password_input is not None else ""
        remember = bool(self.vpn_remember_checkbox is not None and self.vpn_remember_checkbox.isChecked())
        if remember and not username:
            self._show_message("Username is required when saving credentials.", QMessageBox.Warning)
            return
        if remember and not password:
            self._show_message("Password is required when saving credentials.", QMessageBox.Warning)
            return
        self._update_profile_credentials(name, username, password, remember)
        if self.vpn_password_input is not None:
            self.vpn_password_input.clear()
            had_secret = bool(username or password)
            self.vpn_password_input.setPlaceholderText("(stored)" if remember and had_secret else "")
        if self.vpn_remember_checkbox is not None:
            self.vpn_remember_checkbox.setChecked(remember and bool(username or password))
        status = "saved" if remember and (username or password) else "cleared"
        self.append_log(f"VPN credentials {status} for '{name}'.", "task")

    def _vpn_connect(self) -> None:
        if self.vpn_process:
            self.append_log("VPN connection already active.", "info")
            self._update_vpn_status("Connected", connected=True)
            return
        name = self._vpn_current_profile_name()
        if not name:
            self._show_message("Select a VPN profile to connect.", QMessageBox.Warning)
            return
        profile = self.vpn_profiles.get(name, {})
        config_path = profile.get("path", "").strip()
        if not config_path:
            self._show_message("Selected profile has no configuration path.", QMessageBox.Warning)
            return
        if not os.path.exists(config_path):
            self._show_message("VPN configuration file could not be found.", QMessageBox.Warning)
            return

        input_username = self.vpn_username_input.text().strip() if self.vpn_username_input is not None else ""
        input_password = self.vpn_password_input.text() if self.vpn_password_input is not None else ""
        stored_user, stored_pass = self._get_stored_credentials(profile)
        remember = bool(self.vpn_remember_checkbox is not None and self.vpn_remember_checkbox.isChecked())

        username = input_username or stored_user
        password = input_password or stored_pass
        if remember:
            self._update_profile_credentials(name, username, password, True)
        else:
            if stored_user or stored_pass or input_username or input_password:
                self._update_profile_credentials(name, "", "", False)

        if not username or not password:
            self._show_message("Username and password are required to establish the VPN connection.", QMessageBox.Warning)
            return

        try:
            auth_path = self._write_vpn_auth_file(username, password)
        except Exception as exc:
            self.append_log(f"Failed to prepare VPN credentials file: {exc}", "error")
            return

        log_path = Path.home() / f".flatline_dixie_{name}_vpn.log"
        try:
            log_handle = open(log_path, "a", encoding="utf-8")
        except OSError as exc:
            self.append_log(f"Unable to open VPN log file: {exc}", "error")
            self._cleanup_vpn_temp_files()
            return

        cmd = [
            "openvpn",
            "--config",
            config_path,
            "--auth-user-pass",
            auth_path,
            "--auth-nocache",
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
        except Exception as exc:
            self.append_log(f"Failed to launch OpenVPN: {exc}", "error")
            log_handle.close()
            self._cleanup_vpn_temp_files()
            return

        self.vpn_process = process
        self.vpn_process_log = log_path
        self.vpn_process_handle = log_handle
        self.vpn_connected_profile = name
        self.append_log(f"Connecting to VPN '{name}' with profile {config_path}.")
        self._update_vpn_status("Connecting...", connected=True)
        if self.vpn_password_input is not None:
            self.vpn_password_input.clear()
            self.vpn_password_input.setPlaceholderText("(stored)")
        self.vpn_status_timer.start()

    def _vpn_disconnect(self) -> None:
        if not self.vpn_process:
            self._update_vpn_status("Disconnected", connected=False)
            return
        try:
            os.killpg(os.getpgid(self.vpn_process.pid), signal.SIGTERM)
            self.append_log(f"Disconnect signal sent to VPN '{self.vpn_connected_profile or 'active'}'.")
        except Exception as exc:
            try:
                self.vpn_process.terminate()
                self.append_log("Fallback terminate issued to VPN process.", "warning")
            except Exception:
                self.append_log(f"Unable to terminate VPN process: {exc}", "error")
        self._update_vpn_status("Disconnecting...", connected=True)

    def _poll_vpn_process(self) -> None:
        if not self.vpn_process:
            self._update_vpn_status("Disconnected", connected=False)
            return
        code = self.vpn_process.poll()
        if code is None:
            label = self.vpn_connected_profile or "Connected"
            self._update_vpn_status(f"Connected ({label})", connected=True)
            return

        profile = self.vpn_connected_profile or "VPN"
        if code == 0:
            self.append_log(f"VPN '{profile}' disconnected cleanly.", "success")
        else:
            self.append_log(f"VPN '{profile}' exited with code {code}.", "error")
        self._cleanup_vpn_temp_files()
        self.vpn_process = None
        self.vpn_connected_profile = None
        self._update_vpn_status("Disconnected", connected=False)

    def _cleanup_vpn_temp_files(self) -> None:
        if self.vpn_auth_file and os.path.exists(self.vpn_auth_file):
            try:
                os.remove(self.vpn_auth_file)
            except Exception as exc:
                self.append_log(f"Unable to remove temporary VPN credential file: {exc}", "warning")
        self.vpn_auth_file = None
        if self.vpn_process_handle:
            try:
                self.vpn_process_handle.close()
            except Exception:
                pass
        self.vpn_process_handle = None
        self.vpn_process_log = None

    def _write_vpn_auth_file(self, username: str, password: str) -> str:
        fd, path = tempfile.mkstemp(prefix="flatdixie_vpn_")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f"{username}\n{password}\n")
        os.chmod(path, 0o600)
        self.vpn_auth_file = path
        return path

    def _prompt_text(self, title: str, label: str, text: str = "") -> tuple:
        new_text, ok = QInputDialog.getText(self, title, label, text=text)
        return new_text.strip(), bool(ok)

    def _copy_file(self, source: str, destination: str) -> None:
        shutil.copyfile(source, destination)

    def _show_message(self, message: str, icon: QMessageBox.Icon = QMessageBox.Information) -> None:
        QMessageBox(icon, "VPN Manager", message, QMessageBox.Ok, self).exec_()


def main() -> None:
    app = QApplication(sys.argv)
    window = FlatlineDixieMainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
