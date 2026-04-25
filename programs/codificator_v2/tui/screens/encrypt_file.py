"""
Encrypt File screen.

Wizard-style flow for encrypting a single file.
"""

import time
from pathlib import Path
from typing import Optional

from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Input, Select, Checkbox, ProgressBar, RadioSet, RadioButton
from textual.binding import Binding
from textual.worker import Worker


class EncryptFileScreen(Screen):
    """Screen for encrypting a single file."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("enter", "submit", "Submit", show=False),
    ]
    
    CSS = """
    EncryptFileScreen {
        align: center middle;
    }
    
    #main-container {
        width: 80;
        height: auto;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
    }
    
    .form-row {
        height: auto;
        margin: 1 0;
    }
    
    .form-label {
        width: 20;
        height: 1;
        content-align: left middle;
    }
    
    .form-input {
        width: 1fr;
    }
    
    #auth-mode-container {
        height: auto;
        margin-bottom: 1;
        border-bottom: solid $secondary;
        padding-bottom: 1;
    }
    
    #container-manual { height: auto; }
    
    #container-key {
        height: auto;
        display: none;
    }
    
    #container-key.visible { display: block; }
    #container-manual.hidden { display: none; }
    
    #key-status {
        color: $warning;
        text-style: italic;
        margin-left: 2;
    }
    
    #progress-container {
        height: auto;
        margin: 1 0;
        display: none;
    }
    #progress-container.visible { display: block; }
    
    #button-row {
        height: 3;
        margin-top: 1;
        align: center middle;
    }
    
    #button-row Button { margin: 0 1; }
    
    #status-label {
        text-align: center;
        margin: 1 0;
    }
    
    .error { color: $error; }
    .success { color: $success; }
    """
    
    def __init__(self):
        super().__init__()
        self._worker: Optional[Worker] = None
        self._keyring_unlocked = False
    
    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            yield Static("═══ ENCRYPT FILE ═══", id="title")
            
            with Horizontal(classes="form-row"):
                yield Label("Source File:", classes="form-label")
                yield Input(placeholder="Path to file...", id="input-source", classes="form-input")
            
            with Horizontal(classes="form-row"):
                yield Label("Output File:", classes="form-label")
                yield Input(placeholder="Path for .codi output...", id="input-dest", classes="form-input")
            
            with Horizontal(classes="form-row"):
                yield Label("Algorithm:", classes="form-label")
                yield Select(
                    [("AES-256-GCM (Recommended)", "aes"), ("ChaCha20-Poly1305", "chacha")],
                    id="select-algo",
                    value="aes"
                )
            
            with Horizontal(classes="form-row"):
                yield Label("Auth Method:", classes="form-label")
                yield Select(
                    [("Manual Password", "mode-manual"), ("Stored Key (Keyring)", "mode-key")],
                    id="select-auth-mode",
                    value="mode-manual"
                )
            
            with Container(id="container-manual"):
                with Horizontal(classes="form-row"):
                    yield Label("Password:", classes="form-label")
                    yield Input(placeholder="Enter password...", password=True, id="input-password", classes="form-input")
                with Horizontal(classes="form-row"):
                    yield Label("Confirm:", classes="form-label")
                    yield Input(placeholder="Confirm password...", password=True, id="input-confirm", classes="form-input")
            
            with Container(id="container-key"):
                with Horizontal(classes="form-row"):
                    yield Label("Select Key:", classes="form-label")
                    yield Select([], id="select-key", prompt="Select a key from vault...", classes="form-input")
                yield Label("", id="key-status")
            
            with Horizontal(classes="form-row"):
                yield Checkbox("Include original filename", id="check-filename", value=True)
                yield Checkbox("Enable compression (V2)", id="check-compress")
            
            with Container(id="progress-container"):
                yield ProgressBar(id="progress-bar", total=100)
                yield Label("", id="progress-label")
            
            yield Label("", id="status-label")
            
            with Horizontal(id="button-row"):
                yield Button("Cancel", id="btn-cancel", variant="default")
                yield Button("Encrypt", id="btn-encrypt", variant="primary")
    
    def on_mount(self) -> None:
        self.query_one("#input-source", Input).focus()
    
    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "select-auth-mode": return
        manual_mode = event.value == "mode-manual"
        
        container_manual = self.query_one("#container-manual")
        container_key = self.query_one("#container-key")
        
        if manual_mode:
            container_manual.remove_class("hidden")
            container_key.remove_class("visible")
        else:
            container_manual.add_class("hidden")
            container_key.add_class("visible")
            self._load_keys()
    
    def _get_keyring(self):
        shared = getattr(self.app, "shared_keyring", None)
        if shared and not shared.is_locked:
            return shared
        from ...core.keyring import Keyring
        return Keyring()

    def _load_keys(self) -> None:
        try:
            keyring = self._get_keyring()
            select = self.query_one("#select-key", Select)
            status = self.query_one("#key-status", Label)
            
            if not keyring.exists:
                status.update("⚠ No keyring found. Create one in 'Key Management'.")
                select.disabled = True
                return
            
            if keyring.is_locked:
                status.update("🔒 Keyring is locked. Unlock it in 'Key Management'.")
                select.disabled = True
                self._keyring_unlocked = False
                return
            
            self._keyring_unlocked = True
            select.disabled = False
            status.update("")
            
            keys = keyring.list_keys()
            options = []
            for k in keys:
                options.append((f"{k.name} ({k.algorithm.name})", k.key_id))
            
            if not options:
                status.update("⚠ Keyring is empty.")
            
            select.set_options(options)
            
        except Exception as e:
            self.query_one("#key-status", Label).update(f"Error: {e}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel": self.action_go_back()
        elif event.button.id == "btn-encrypt": self._start_encryption()
    
    def action_go_back(self) -> None:
        if self._worker and self._worker.is_running: self._worker.cancel()
        self.app.pop_screen()
    
    def _get_encryption_password(self) -> Optional[str]:
        val = self.query_one("#select-auth-mode", Select).value
        if val is None: return None
        is_manual = val == "mode-manual"
        
        if is_manual:
            pw = self.query_one("#input-password", Input).value
            confirm = self.query_one("#input-confirm", Input).value
            if not pw:
                self._show_status("Please enter a password", is_error=True)
                return None
            if len(pw) < 12:
                self._show_status("Password too short (<12 chars)", is_error=True)
                return None
            if pw != confirm:
                self._show_status("Passwords do not match", is_error=True)
                return None
            return pw
        else:
            if not self._keyring_unlocked:
                self._show_status("Keyring is locked! Unlock it first.", is_error=True)
                return None
            
            target_id = self.query_one("#select-key", Select).value
            if not target_id:
                self._show_status("Please select a key", is_error=True)
                return None
            
            try:
                keyring = self._get_keyring()
                found_key = None
                all_keys = keyring.list_keys()
                
                for k in all_keys:
                    if str(k.key_id) == str(target_id):
                        found_key = k
                        break
                
                if not found_key:
                    raise Exception(f"Key ID not found: {target_id}")

                keyring.increment_use(found_key.key_id)
                return found_key.secret_value if hasattr(found_key, 'secret_value') else found_key.name

            except Exception as e:
                self._show_status(f"Failed to retrieve key: {e}", is_error=True)
                return None

    def _start_encryption(self) -> None:
        src = self.query_one("#input-source", Input).value.strip()
        dst = self.query_one("#input-dest", Input).value.strip()
        
        if not src:
            self._show_status("Please enter source file", is_error=True)
            return
        if not Path(src).exists():
            self._show_status("Source file not found", is_error=True)
            return
        if Path(src).is_dir():
            self._show_status("Source is a directory!", is_error=True)
            return
        if not dst:
            self._show_status("Please enter output path", is_error=True)
            return
        if Path(dst).is_dir():
            self._show_status("Output path is a directory!", is_error=True)
            return

        password = self._get_encryption_password()
        if not password: return
        
        algo_str = self.query_one("#select-algo", Select).value
        include_filename = self.query_one("#check-filename", Checkbox).value
        compress = self.query_one("#check-compress", Checkbox).value
        
        from ...core import Algorithm
        algorithm = Algorithm.CHACHA20_POLY1305 if "ChaCha" in str(algo_str) else Algorithm.AES_256_GCM
        
        self.query_one("#progress-container").add_class("visible")
        self._show_status("Encrypting...", is_error=False)
        
        self._worker = self._do_encrypt(src, dst, password, algorithm, include_filename, compress)
    
    @work(thread=True, name="encrypt")
    def _do_encrypt(self, src: str, dst: str, password: str,
                          algorithm, include_filename: bool, compress: bool) -> None:
        # [AJOUT AUDIT] On importe les types nécessaires
        from ...core import CompressionType, ContainerVersion, OperationType
        from ...core.vault import SecureVault
        from ...core.audit import AuditLogger
        
        start_time = time.time()
        
        try:
            # [AJOUT AUDIT] On prépare le logger
            logger = AuditLogger()
            
            compression = CompressionType.ZLIB if compress else CompressionType.NONE
            version = ContainerVersion.V2 if compress else ContainerVersion.V1
            
            vault = SecureVault(
                algorithm=algorithm,
                container_version=version,
                compression=compression
            )
            
            def progress_callback(current, total, msg):
                if total > 0:
                    pct = int(current / total * 100)
                    self.app.call_from_thread(self._update_progress, pct, msg)
            
            result = vault.encrypt_file(
                src, dst, password,
                include_filename=include_filename,
                progress_callback=progress_callback
            )
            
            # [AJOUT AUDIT] C'est ICI qu'on enregistre l'événement
            duration = int((time.time() - start_time) * 1000)
            file_size = result.get('dst_size', 0)
            
            try:
                # Appel qui correspond exactement à ton fichier audit.py
                logger.log_operation(
                    operation=OperationType.ENCRYPT_FILE,
                    src_path=src,
                    dst_path=dst,
                    status="success",
                    algorithm=algorithm.name,
                    duration_ms=duration,
                    total_bytes=file_size
                )
            except Exception:
                pass # On évite de planter si le log échoue
            
            self.app.call_from_thread(self._on_success, result)
            
        except Exception as e:
            # [AJOUT AUDIT] On enregistre aussi l'échec
            duration = int((time.time() - start_time) * 1000)
            try:
                logger = AuditLogger()
                logger.log_operation(
                    operation=OperationType.ENCRYPT_FILE,
                    src_path=src,
                    dst_path=dst,
                    status="failed",
                    algorithm=algorithm.name,
                    duration_ms=duration,
                    error_message=str(e)
                )
            except Exception:
                pass

            self.app.call_from_thread(self._on_error, str(e))
    
    def _update_progress(self, pct: int, msg: str) -> None:
        self.query_one("#progress-bar", ProgressBar).update(progress=pct)
        self.query_one("#progress-label", Label).update(msg)
    
    def _on_success(self, result: dict) -> None:
        self.query_one("#progress-container").remove_class("visible")
        self._show_status(
            f"✓ Encryption complete! Size: {result.get('dst_size', 0)} bytes",
            is_error=False
        )
        self.query_one("#input-password", Input).value = ""
        self.query_one("#input-confirm", Input).value = ""
    
    def _on_error(self, error: str) -> None:
        self.query_one("#progress-container").remove_class("visible")
        self._show_status(f"Error: {error}", is_error=True)
    
    def _show_status(self, message: str, is_error: bool) -> None:
        label = self.query_one("#status-label", Label)
        label.update(message)
        label.remove_class("success", "error")
        if message:
            label.add_class("error" if is_error else "success")