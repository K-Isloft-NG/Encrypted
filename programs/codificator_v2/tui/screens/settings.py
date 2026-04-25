"""
Settings screen.

Configure application settings and security policies.
"""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Select, Checkbox, Input
from textual.binding import Binding


class SettingsScreen(Screen):
    """Screen for application settings."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    CSS = """
    SettingsScreen {
        align: center middle;
    }
    
    #main-container {
        width: 80;
        height: auto;
        max-height: 90%;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
        overflow-y: auto;
    }
    
    .section-title {
        margin: 1 0;
        text-style: bold;
        color: $primary;
    }
    
    .setting-row {
        height: auto;
        margin: 0 0 1 0;
    }
    
    .setting-label {
        width: 30;
    }
    
    .setting-input {
        width: 1fr;
    }
    
    #button-row {
        height: 3;
        margin-top: 2;
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
    
    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            yield Static("═══ SETTINGS ═══", id="title")
            
            # Security Profile
            yield Label("── Security Profile ──", classes="section-title")
            with Horizontal(classes="setting-row"):
                yield Label("Profile:", classes="setting-label")
                yield Select(
                    [("Personal", "personal"), ("Work", "work"), ("Forensic", "forensic")],
                    id="select-profile",
                    value="personal"
                )
            
            # Encryption Settings
            yield Label("── Encryption ──", classes="section-title")
            with Horizontal(classes="setting-row"):
                yield Label("Default Algorithm:", classes="setting-label")
                yield Select(
                    [("AES-256-GCM", "aes"), ("ChaCha20-Poly1305", "chacha")],
                    id="select-algo",
                    value="aes"
                )
            
            with Horizontal(classes="setting-row"):
                yield Label("Container Version:", classes="setting-label")
                yield Select(
                    [("V1 (Compatible)", "1"), ("V2 (Compression)", "2")],
                    id="select-version",
                    value="2"
                )
            
            with Horizontal(classes="setting-row"):
                yield Checkbox("Enable compression (V2 only)", id="check-compress", value=False)
            
            # KDF Settings
            yield Label("── Key Derivation (scrypt) ──", classes="section-title")
            with Horizontal(classes="setting-row"):
                yield Label("scrypt N (CPU cost):", classes="setting-label")
                yield Select(
                    [("16384 (Fast)", "14"), ("32768 (Default)", "15"), ("65536 (Secure)", "16"), ("131072 (Paranoid)", "17")],
                    id="select-scrypt-n",
                    value="15"
                )
            
            # Password Policy
            yield Label("── Password Policy ──", classes="section-title")
            with Horizontal(classes="setting-row"):
                yield Label("Min password length:", classes="setting-label")
                yield Select(
                    [("8 characters", "8"), ("12 characters", "12"), ("16 characters", "16"), ("20 characters", "20")],
                    id="select-min-pw",
                    value="12"
                )
            
            # Audit Settings
            yield Label("── Audit Logging ──", classes="section-title")
            with Horizontal(classes="setting-row"):
                yield Checkbox("Enable audit logging", id="check-audit", value=True)
            with Horizontal(classes="setting-row"):
                yield Checkbox("Paranoid mode (hash paths)", id="check-paranoid", value=False)
            
            # Batch Settings
            yield Label("── Batch Operations ──", classes="section-title")
            with Horizontal(classes="setting-row"):
                yield Label("Max parallel jobs:", classes="setting-label")
                yield Select(
                    [("1 (Sequential)", "1"), ("2", "2"), ("4 (Default)", "4"), ("8", "8")],
                    id="select-jobs",
                    value="4"
                )
            with Horizontal(classes="setting-row"):
                yield Checkbox("Continue on error", id="check-continue", value=True)
            
            yield Label("", id="status-label")
            
            with Horizontal(id="button-row"):
                yield Button("Back", id="btn-back", variant="default")
                yield Button("Reset Defaults", id="btn-reset", variant="warning")
                yield Button("Save", id="btn-save", variant="primary")
    
    def on_mount(self) -> None:
        self._load_settings()
    
    def _load_settings(self) -> None:
        """Load current settings."""
        # In a full implementation, would load from config file
        pass
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.action_go_back()
        elif event.button.id == "btn-save":
            self._save_settings()
        elif event.button.id == "btn-reset":
            self._reset_defaults()
    
    def action_go_back(self) -> None:
        self.app.pop_screen()
    
    def _save_settings(self) -> None:
        """Save settings to config file."""
        try:
            def safe_int(val, default):
                try:
                    return int(str(val))
                except (ValueError, TypeError):
                    return default
            # Collect settings
            settings = {
                "profile": str(self.query_one("#select-profile", Select).value),
                "algorithm": str(self.query_one("#select-algo", Select).value),
                "container_version": safe_int(self.query_one("#select-version", Select).value, 2),
                "compression": self.query_one("#check-compress", Checkbox).value,
                "scrypt_n": 2 ** safe_int(self.query_one("#select-scrypt-n", Select).value, 15),
                "min_password_length": safe_int(self.query_one("#select-min-pw", Select).value, 12),
                "audit_enabled": self.query_one("#check-audit", Checkbox).value,
                "paranoid_mode": self.query_one("#check-paranoid", Checkbox).value,
                "max_workers": safe_int(self.query_one("#select-jobs", Select).value, 4),
                "continue_on_error": self.query_one("#check-continue", Checkbox).value,
            }
            
            # Save to config file
            import json
            from pathlib import Path
            config_path = Path.home() / ".codificator_config.json"
            
            with open(config_path, 'w') as f:
                json.dump(settings, f, indent=2)
            
            self._show_status("Settings saved!", is_error=False)
            
        except Exception as e:
            self._show_status(f"Error saving: {e}", is_error=True)
    
    def _reset_defaults(self) -> None:
        """Reset to default settings."""
        self.query_one("#select-profile", Select).value = "personal"
        self.query_one("#select-algo", Select).value = "aes"
        self.query_one("#select-version", Select).value = "2"
        self.query_one("#check-compress", Checkbox).value = False
        self.query_one("#select-scrypt-n", Select).value = "15"
        self.query_one("#select-min-pw", Select).value = "12"
        self.query_one("#check-audit", Checkbox).value = True
        self.query_one("#check-paranoid", Checkbox).value = False
        self.query_one("#select-jobs", Select).value = "4"
        self.query_one("#check-continue", Checkbox).value = True
        
        self._show_status("Reset to defaults", is_error=False)
    
    def _show_status(self, message: str, is_error: bool) -> None:
        label = self.query_one("#status-label", Label)
        label.update(message)
        label.remove_class("success", "error")
        if message:
            label.add_class("error" if is_error else "success")
