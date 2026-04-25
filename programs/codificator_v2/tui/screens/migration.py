"""
Migration screen.

Migrate .codi files from V1 to V2 format.
"""

from pathlib import Path
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Input, Checkbox, ProgressBar, Log
from textual.binding import Binding
from textual.worker import Worker


class MigrationScreen(Screen):
    """Screen for migrating .codi files between versions."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    CSS = """
    MigrationScreen {
        align: center middle;
    }
    
    #main-container {
        width: 85;
        height: auto;
        max-height: 90%;
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
    
    #info-box {
        height: auto;
        margin: 1 0;
        padding: 1;
        border: solid $warning;
        background: $surface-lighten-1;
    }
    
    #progress-log {
        height: 8;
        margin: 1 0;
        border: solid $secondary;
        display: none;
    }
    
    #progress-log.visible {
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
            yield Static("═══ MIGRATION: V1 → V2 ═══", id="title")
            
            with Container(id="info-box"):
                yield Static("""Migration converts .codi files from V1 to V2 format.

V2 benefits:
• Optional compression (zlib) - smaller files
• Improved chunk table
• Better metadata handling

Note: V1 files remain readable. Migration is optional.""")
            
            with Horizontal(classes="form-row"):
                yield Label("Source:", classes="form-label")
                yield Input(placeholder="File or folder path...", id="input-source", classes="form-input")
            
            with Horizontal(classes="form-row"):
                yield Label("Output:", classes="form-label")
                yield Input(placeholder="Output path (or empty for in-place)", id="input-dest", classes="form-input")
            
            with Horizontal(classes="form-row"):
                yield Label("Password:", classes="form-label")
                yield Input(placeholder="Password for re-encryption...", password=True, id="input-password", classes="form-input")
            
            with Horizontal(classes="form-row"):
                yield Checkbox("Enable compression", id="check-compress", value=True)
                yield Checkbox("Delete original after migration", id="check-delete", value=False)
                yield Checkbox("Recursive (for folders)", id="check-recursive", value=True)
            
            yield Log(id="progress-log", highlight=True)
            
            with Horizontal(classes="form-row"):
                yield ProgressBar(id="progress-bar", total=100)
            
            yield Label("", id="status-label")
            
            with Horizontal(id="button-row"):
                yield Button("Back", id="btn-back", variant="default")
                yield Button("Check File", id="btn-check", variant="default")
                yield Button("Migrate", id="btn-migrate", variant="primary")
    
    def on_mount(self) -> None:
        self.query_one("#input-source", Input).focus()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.action_go_back()
        elif event.button.id == "btn-check":
            self._check_file()
        elif event.button.id == "btn-migrate":
            self._start_migration()
    
    def action_go_back(self) -> None:
        if self._worker and self._worker.is_running:
            self._worker.cancel()
        self.app.pop_screen()
    
    def _check_file(self) -> None:
        """Check file version."""
        src = self.query_one("#input-source", Input).value.strip()
        
        if not src:
            self._show_status("Please enter source path", is_error=True)
            return
        
        path = Path(src)
        if not path.exists():
            self._show_status(f"Path not found: {src}", is_error=True)
            return
        
        if path.is_dir():
            self._show_status("Selected a folder - will migrate all .codi files", is_error=False)
            return
        
        try:
            from ...core.container_v2 import detect_version, get_container_info
            
            version = detect_version(path)
            info = get_container_info(path)
            
            if version == 1:
                msg = f"File is V1 format - can be migrated to V2"
            else:
                msg = f"File is already V2 format"
            
            if info.get('compressed'):
                msg += " (compressed)"
            
            self._show_status(msg, is_error=False)
            
        except Exception as e:
            self._show_status(f"Error checking file: {e}", is_error=True)
    
    def _validate_inputs(self) -> Optional[str]:
        src = self.query_one("#input-source", Input).value.strip()
        password = self.query_one("#input-password", Input).value
        
        if not src:
            return "Please enter source path"
        if not Path(src).exists():
            return f"Path not found: {src}"
        if not password:
            return "Please enter password"
        if len(password) < 12:
            return "Password must be at least 12 characters"
        
        return None
    
    def _start_migration(self) -> None:
        error = self._validate_inputs()
        if error:
            self._show_status(error, is_error=True)
            return
        
        src = self.query_one("#input-source", Input).value.strip()
        dst = self.query_one("#input-dest", Input).value.strip() or None
        password = self.query_one("#input-password", Input).value
        compress = self.query_one("#check-compress", Checkbox).value
        delete_original = self.query_one("#check-delete", Checkbox).value
        recursive = self.query_one("#check-recursive", Checkbox).value
        
        self.query_one("#progress-log").add_class("visible")
        self.query_one("#progress-log", Log).clear()
        self._show_status("Migrating...", is_error=False)
        
        self._worker = self.run_worker(
            self._do_migrate(src, dst, password, compress, delete_original, recursive),
            name="migrate"
        )
    
    async def _do_migrate(self, src: str, dst: Optional[str], password: str,
                          compress: bool, delete_original: bool, 
                          recursive: bool) -> None:
        from ...core.migrate import Migrator
        from ...core import CompressionType
        
        try:
            path = Path(src)
            compression = CompressionType.ZLIB if compress else CompressionType.NONE
            migrator = Migrator(compression=compression)
            
            if path.is_file():
                # Single file migration
                self.app.call_from_thread(self._log, f"Migrating: {path.name}")
                
                dst_path = Path(dst) if dst else path
                result = migrator.migrate_file(path, dst_path, password)
                
                if delete_original and dst_path != path:
                    path.unlink()
                
                self.app.call_from_thread(self._on_success, result)
            else:
                # Folder migration
                def progress_callback(current, total, filename):
                    self.app.call_from_thread(self._log, f"[{current}/{total}] {filename}")
                    if total > 0:
                        pct = int(current / total * 100)
                        self.app.call_from_thread(self._update_bar, pct)
                
                dst_path = Path(dst) if dst else path
                result = migrator.migrate_folder(
                    path, dst_path, password,
                    recursive=recursive,
                    progress_callback=progress_callback
                )
                
                if delete_original and dst_path != path:
                    import shutil
                    shutil.rmtree(path)
                
                self.app.call_from_thread(self._on_folder_success, result)
                
        except Exception as e:
            self.app.call_from_thread(self._on_error, str(e))
    
    def _log(self, msg: str) -> None:
        self.query_one("#progress-log", Log).write_line(msg)
    
    def _update_bar(self, pct: int) -> None:
        self.query_one("#progress-bar", ProgressBar).update(progress=pct)
    
    def _on_success(self, result: dict) -> None:
        old_v = result.get('old_version', 1)
        new_v = result.get('new_version', 2)
        self._show_status(f"✓ Migrated from V{old_v} to V{new_v}", is_error=False)
        self.query_one("#input-password", Input).value = ""
    
    def _on_folder_success(self, result: dict) -> None:
        succeeded = result.get('succeeded', 0)
        failed = result.get('failed', 0)
        skipped = result.get('skipped', 0)
        self._show_status(
            f"✓ Migration complete: {succeeded} migrated, {skipped} skipped, {failed} failed",
            is_error=failed > 0
        )
        self.query_one("#input-password", Input).value = ""
    
    def _on_error(self, error: str) -> None:
        if "Integrity" in error:
            error = "Migration failed: wrong password or file tampered"
        self._show_status(f"Error: {error}", is_error=True)
    
    def _show_status(self, message: str, is_error: bool) -> None:
        label = self.query_one("#status-label", Label)
        label.update(message)
        label.remove_class("success", "error")
        if message:
            label.add_class("error" if is_error else "success")
