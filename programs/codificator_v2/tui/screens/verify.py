"""
Verify File screen.

Check integrity of a .codi file without full decryption.
"""

from pathlib import Path
from typing import Optional

# [CORRECTION] Import de 'work' pour gérer le threading et éviter le crash
from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Input, ProgressBar
from textual.binding import Binding
from textual.worker import Worker


class VerifyScreen(Screen):
    """Screen for verifying .codi file integrity."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    CSS = """
    VerifyScreen {
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
    
    #result-container {
        height: auto;
        margin: 1 0;
        padding: 1;
        border: solid $secondary;
        display: none;
    }
    
    #result-container.visible {
        display: block;
    }
    
    .valid {
        border: solid $success;
    }
    
    .invalid {
        border: solid $error;
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
            yield Static("═══ VERIFY FILE ═══", id="title")
            
            with Horizontal(classes="form-row"):
                yield Label("File (.codi):", classes="form-label")
                yield Input(placeholder="Path to .codi file...", id="input-file", classes="form-input")
            
            with Horizontal(classes="form-row"):
                yield Label("Password:", classes="form-label")
                yield Input(placeholder="Enter password to verify...", password=True, id="input-password", classes="form-input")
            
            with Container(id="result-container"):
                yield Static("Verification Result:", id="result-title")
                yield Label("", id="result-content")
            
            yield Label("", id="status-label")
            
            with Horizontal(id="button-row"):
                yield Button("Back", id="btn-cancel", variant="default")
                yield Button("Get Info", id="btn-info", variant="default")
                yield Button("Verify", id="btn-verify", variant="primary")
    
    def on_mount(self) -> None:
        self.query_one("#input-file", Input).focus()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.action_go_back()
        elif event.button.id == "btn-info":
            self._show_info()
        elif event.button.id == "btn-verify":
            self._start_verify()
    
    def action_go_back(self) -> None:
        if self._worker and self._worker.is_running:
            self._worker.cancel()
        self.app.pop_screen()
    
    def _show_info(self) -> None:
        """Show file info without password."""
        file_path = self.query_one("#input-file", Input).value.strip()
        
        if not file_path:
            self._show_status("Please enter file path", is_error=True)
            return
        
        path = Path(file_path)
        if not path.exists():
            self._show_status(f"File not found: {file_path}", is_error=True)
            return
            
        # Sécurité : On vérifie que ce n'est pas un dossier
        if path.is_dir():
            self._show_status("Selected path is a directory", is_error=True)
            return
        
        try:
            from ...core.container_v2 import get_container_info
            info = get_container_info(path)
            
            lines = [
                f"Version: {info.get('version', 'Unknown')}",
                f"Algorithm: {info.get('algorithm', 'Unknown')}",
                f"KDF: {info.get('kdf', 'Unknown')}",
                f"Chunked: {'Yes' if info.get('chunked') else 'No'}",
            ]
            
            if info.get('original_filename'):
                lines.append(f"Original: {info['original_filename']}")
            if info.get('created_at'):
                lines.append(f"Created: {info['created_at']}")
            if info.get('compressed'):
                lines.append(f"Compressed: Yes")
            
            lines.append(f"scrypt N: {info.get('scrypt_n', 'N/A')}")
            
            self.query_one("#result-content", Label).update('\n'.join(lines))
            container = self.query_one("#result-container")
            container.add_class("visible")
            container.remove_class("valid", "invalid")
            self._show_status("", is_error=False)
            
        except Exception as e:
            self._show_status(f"Cannot read file: {e}", is_error=True)
    
    def _validate_inputs(self) -> Optional[str]:
        file_path = self.query_one("#input-file", Input).value.strip()
        password = self.query_one("#input-password", Input).value
        
        if not file_path:
            return "Please enter file path"
            
        path = Path(file_path)
        if not path.exists():
            return f"File not found: {file_path}"
        
        # Sécurité : Empêche le crash si l'utilisateur met un dossier
        if path.is_dir():
            return "Selected path is a directory! Please select a .codi file."
            
        if not password:
            return "Please enter password to verify"
        
        return None
    
    def _start_verify(self) -> None:
        error = self._validate_inputs()
        if error:
            self._show_status(error, is_error=True)
            return
        
        file_path = self.query_one("#input-file", Input).value.strip()
        password = self.query_one("#input-password", Input).value
        
        self._show_status("Verifying...", is_error=False)
        
        # [CORRECTION] Appel direct de la méthode threadée (plus besoin de self.run_worker)
        self._worker = self._do_verify(file_path, password)
    
    # [CORRECTION] @work(thread=True) pour exécuter dans un thread séparé
    @work(thread=True, name="verify")
    def _do_verify(self, file_path: str, password: str) -> None:
        from ...core.vault import SecureVault
        
        try:
            vault = SecureVault()
            # Cette opération est lourde (CPU-bound)
            is_valid, info = vault.verify_file(file_path, password)
            
            # On utilise call_from_thread pour mettre à jour l'UI en sécurité
            self.app.call_from_thread(self._on_result, is_valid, info)
            
        except Exception as e:
            self.app.call_from_thread(self._on_error, str(e))
    
    def _on_result(self, is_valid: bool, info: dict) -> None:
        container = self.query_one("#result-container")
        container.add_class("visible")
        container.remove_class("valid", "invalid")
        
        if is_valid:
            container.add_class("valid")
            lines = ["✓ FILE IS VALID", ""]
            lines.append(f"Algorithm: {info.get('algorithm', 'Unknown')}")
            if info.get('original_filename'):
                lines.append(f"Original: {info['original_filename']}")
            self._show_status("✓ Verification passed!", is_error=False)
        else:
            container.add_class("invalid")
            lines = ["✗ VERIFICATION FAILED", ""]
            lines.append(info.get('error', 'Wrong password or file tampered'))
            self._show_status("✗ Verification failed", is_error=True)
        
        self.query_one("#result-content", Label).update('\n'.join(lines))
        self.query_one("#input-password", Input).value = ""
    
    def _on_error(self, error: str) -> None:
        if "Integrity" in error:
            error = "Wrong password or file tampered"
        self._show_status(f"Error: {error}", is_error=True)
    
    def _show_status(self, message: str, is_error: bool) -> None:
        label = self.query_one("#status-label", Label)
        label.update(message)
        label.remove_class("success", "error")
        if message:
            label.add_class("error" if is_error else "success")