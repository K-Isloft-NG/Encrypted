"""
Decrypt File screen.

Wizard-style flow for decrypting a .codi file.
"""

import time
from pathlib import Path
from typing import Optional

from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Input, ProgressBar
from textual.binding import Binding
from textual.worker import Worker


class DecryptFileScreen(Screen):
    """Screen for decrypting a .codi file."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    CSS = """
    DecryptFileScreen {
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
    }
    
    .form-input {
        width: 1fr;
    }
    
    #info-container {
        height: auto;
        margin: 1 0;
        padding: 1;
        border: solid $secondary;
        display: none;
    }
    
    #info-container.visible {
        display: block;
    }
    
    #progress-container {
        height: auto;
        margin: 1 0;
        display: none;
    }
    
    #progress-container.visible {
        display: block;
    }
    
    #button-row {
        height: 3;
        margin-top: 1;
        align: center middle;
    }
    
    #button-row Button {
        margin: 0 1;
    }
    
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
    
    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            yield Static("═══ DECRYPT FILE ═══", id="title")
            
            with Horizontal(classes="form-row"):
                yield Label("Source (.codi):", classes="form-label")
                yield Input(placeholder="Path to .codi file...", id="input-source", classes="form-input")
            
            with Horizontal(classes="form-row"):
                yield Button("Get Info", id="btn-info", variant="default")
            
            with Container(id="info-container"):
                yield Static("File Information:", id="info-title")
                yield Label("", id="info-content")
            
            with Horizontal(classes="form-row"):
                yield Label("Output File:", classes="form-label")
                yield Input(placeholder="Path for decrypted output...", id="input-dest", classes="form-input")
            
            with Horizontal(classes="form-row"):
                yield Label("Password:", classes="form-label")
                yield Input(placeholder="Enter password...", password=True, id="input-password", classes="form-input")
            
            with Container(id="progress-container"):
                yield ProgressBar(id="progress-bar", total=100)
                yield Label("", id="progress-label")
            
            yield Label("", id="status-label")
            
            with Horizontal(id="button-row"):
                yield Button("Cancel", id="btn-cancel", variant="default")
                yield Button("Decrypt", id="btn-decrypt", variant="primary")
    
    def on_mount(self) -> None:
        self.query_one("#input-source", Input).focus()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.action_go_back()
        elif event.button.id == "btn-decrypt":
            self._start_decryption()
        elif event.button.id == "btn-info":
            self._show_file_info()
    
    def action_go_back(self) -> None:
        if self._worker and self._worker.is_running:
            self._worker.cancel()
        self.app.pop_screen()
    
    def _show_file_info(self) -> None:
        src = self.query_one("#input-source", Input).value.strip()
        
        if not src:
            self._show_status("Please enter source file path", is_error=True)
            return
        
        src_path = Path(src)
        if not src_path.exists():
            self._show_status(f"File not found: {src}", is_error=True)
            return
        
        if src_path.is_dir():
            self._show_status("Selected path is a directory, not a .codi file", is_error=True)
            return
        
        try:
            from ...core.container_v2 import get_container_info
            info = get_container_info(src_path)
            
            info_text = []
            info_text.append(f"Version: {info.get('version', 'Unknown')}")
            info_text.append(f"Algorithm: {info.get('algorithm', 'Unknown')}")
            info_text.append(f"Chunked: {'Yes' if info.get('chunked') else 'No'}")
            
            if info.get('original_filename'):
                info_text.append(f"Original name: {info['original_filename']}")
                dest_input = self.query_one("#input-dest", Input)
                if not dest_input.value:
                    dest_input.value = info['original_filename']
            
            if info.get('created_at'):
                info_text.append(f"Created: {info['created_at']}")
            
            if info.get('compressed'):
                info_text.append(f"Compressed: Yes ({info.get('compression_type', 'zlib')})")
            
            self.query_one("#info-content", Label).update('\n'.join(info_text))
            self.query_one("#info-container").add_class("visible")
            self._show_status("", is_error=False)
            
        except Exception as e:
            self._show_status(f"Cannot read file info: {e}", is_error=True)
    
    def _validate_inputs(self) -> Optional[str]:
        src = self.query_one("#input-source", Input).value.strip()
        dst = self.query_one("#input-dest", Input).value.strip()
        password = self.query_one("#input-password", Input).value
        
        if not src:
            return "Please enter source file path"
        if not Path(src).exists():
            return f"Source file not found: {src}"
        if Path(src).is_dir():
            return "Source is a directory, please select a .codi file"
        if not dst:
            return "Please enter output file path"
        if Path(dst).is_dir():
            return "Output path is a directory! Please specify a filename."
        if not password:
            return "Please enter the password"
        
        return None
    
    def _start_decryption(self) -> None:
        error = self._validate_inputs()
        if error:
            self._show_status(error, is_error=True)
            return
        
        src = self.query_one("#input-source", Input).value.strip()
        dst = self.query_one("#input-dest", Input).value.strip()
        password = self.query_one("#input-password", Input).value
        
        self.query_one("#progress-container").add_class("visible")
        self._show_status("Decrypting...", is_error=False)
        
        self._worker = self._do_decrypt(src, dst, password)
    
    @work(thread=True, name="decrypt")
    def _do_decrypt(self, src: str, dst: str, password: str) -> None:
        # [AJOUT AUDIT]
        from ...core.vault import SecureVault
        from ...core.audit import AuditLogger
        from ...core import OperationType
        
        start_time = time.time()
        
        try:
            vault = SecureVault()
            
            def progress_callback(current, total, msg):
                if total > 0:
                    pct = int(current / total * 100)
                    self.app.call_from_thread(self._update_progress, pct, msg)
            
            result = vault.decrypt_file(
                src, dst, password,
                progress_callback=progress_callback
            )
            
            # [AJOUT AUDIT] Log Succès
            duration = int((time.time() - start_time) * 1000)
            try:
                logger = AuditLogger()
                logger.log_operation(
                    operation=OperationType.DECRYPT_FILE,
                    src_path=src,
                    dst_path=dst,
                    status="success",
                    duration_ms=duration,
                    total_bytes=result.get('dst_size', 0)
                )
            except Exception:
                pass

            self.app.call_from_thread(self._on_success, result)
            
        except Exception as e:
            # [AJOUT AUDIT] Log Échec
            duration = int((time.time() - start_time) * 1000)
            try:
                logger = AuditLogger()
                logger.log_operation(
                    operation=OperationType.DECRYPT_FILE,
                    src_path=src,
                    dst_path=dst,
                    status="failed",
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
            f"✓ Decryption complete! Size: {result.get('dst_size', 0)} bytes",
            is_error=False
        )
        self.query_one("#input-password", Input).value = ""
    
    def _on_error(self, error: str) -> None:
        self.query_one("#progress-container").remove_class("visible")
        if "Integrity" in error or "tag" in error.lower():
            error = "Decryption failed: wrong password or file tampered"
        self._show_status(f"Error: {error}", is_error=True)
    
    def _show_status(self, message: str, is_error: bool) -> None:
        label = self.query_one("#status-label", Label)
        label.update(message)
        label.remove_class("success", "error")
        if message:
            label.add_class("error" if is_error else "success")