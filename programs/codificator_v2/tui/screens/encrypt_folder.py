"""
Encrypt Folder screen.

Batch encryption of all files in a directory with Keyring support.
"""

import time
from pathlib import Path
from typing import Optional

from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Input, Select, Checkbox, ProgressBar, Log, RadioSet, RadioButton
from textual.binding import Binding
from textual.worker import Worker


class EncryptFolderScreen(Screen):
    """Screen for batch encrypting a folder."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    CSS = """
    EncryptFolderScreen {
        align: center middle;
    }
    
    #main-container {
        width: 90;
        height: 90%;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
        layout: vertical;
    }
    
    #form-scroll {
        height: 1fr;
        overflow-y: auto;
        margin-bottom: 1;
        border-bottom: solid $secondary 50%;
    }
    
    .form-row { height: auto; margin: 1 0; }
    .form-label { width: 20; height: 1; content-align: left middle; }
    .form-input { width: 1fr; }
    
    /* Styles Keyring / Auth */
    #auth-mode-container {
        height: auto;
        margin-bottom: 1;
        border-bottom: solid $secondary;
        padding-bottom: 1;
    }
    #container-manual { height: auto; }
    #container-key { height: auto; display: none; }
    #container-key.visible { display: block; }
    #container-manual.hidden { display: none; }
    
    #key-status {
        color: $warning;
        text-style: italic;
        margin-left: 2;
    }
    
    #progress-log {
        height: 10; margin: 1 0; border: solid $secondary; display: none;
    }
    #progress-log.visible { display: block; }
    
    #button-row {
        height: 4; dock: bottom; align: center middle; padding-top: 1;
    }
    #button-row Button { margin: 0 1; }
    
    #status-label { text-align: center; margin: 1 0; }
    .error { color: $error; }
    .success { color: $success; }
    """
    
    def __init__(self):
        super().__init__()
        self._worker: Optional[Worker] = None
        self._keyring_unlocked = False
    
    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            yield Static("═══ ENCRYPT FOLDER ═══", id="title")
            
            with VerticalScroll(id="form-scroll"):
                # Chemins Source / Dest
                with Horizontal(classes="form-row"):
                    yield Label("Source Folder:", classes="form-label")
                    yield Input(placeholder="Path to folder...", id="input-source", classes="form-input")
                with Horizontal(classes="form-row"):
                    yield Label("Output Folder:", classes="form-label")
                    yield Input(placeholder="Path for encrypted files...", id="input-dest", classes="form-input")
                
                # Algorithme
                with Horizontal(classes="form-row"):
                    yield Label("Algorithm:", classes="form-label")
                    yield Select(
                        [("AES-256-GCM (Recommended)", "aes"), ("ChaCha20-Poly1305", "chacha")],
                        id="select-algo", value="aes"
                    )
                
                # --- SÉLECTION MODE AUTHENTIFICATION ---
                with Horizontal(classes="form-row"):
                    yield Label("Auth Method:", classes="form-label")
                    yield Select(
                        [("Manual Password", "mode-manual"), ("Stored Key (Keyring)", "mode-key")],
                        id="select-auth-mode",
                        value="mode-manual"
                    )
                
                # Mode 1 : Manuel
                with Container(id="container-manual"):
                    with Horizontal(classes="form-row"):
                        yield Label("Password:", classes="form-label")
                        yield Input(placeholder="Enter password...", password=True, id="input-password", classes="form-input")
                    with Horizontal(classes="form-row"):
                        yield Label("Confirm:", classes="form-label")
                        yield Input(placeholder="Confirm password...", password=True, id="input-confirm", classes="form-input")
                
                # Mode 2 : Keyring
                with Container(id="container-key"):
                    with Horizontal(classes="form-row"):
                        yield Label("Select Key:", classes="form-label")
                        yield Select([], id="select-key", prompt="Select a key from vault...", classes="form-input")
                    yield Label("", id="key-status")

                # Options de filtrage
                with Horizontal(classes="form-row"):
                    yield Label("Include:", classes="form-label")
                    yield Input(placeholder="e.g. *.txt,*.json (empty=all)", id="input-include", classes="form-input")
                with Horizontal(classes="form-row"):
                    yield Label("Exclude:", classes="form-label")
                    yield Input(placeholder="e.g. node_modules,*.tmp", id="input-exclude", classes="form-input")
                
                # Options d'exécution
                with Horizontal(classes="form-row"):
                    yield Checkbox("Recursive", id="check-recursive", value=True)
                    yield Checkbox("Dry run (preview only)", id="check-dryrun")
                    yield Checkbox("Continue on error", id="check-continue", value=True)
                
                yield Log(id="progress-log", highlight=True)
                with Horizontal(classes="form-row"):
                    yield ProgressBar(id="progress-bar", total=100)
                yield Label("", id="status-label")
            
            with Horizontal(id="button-row"):
                yield Button("Cancel", id="btn-cancel", variant="default")
                yield Button("Encrypt Folder", id="btn-encrypt", variant="primary")
    
    def on_mount(self) -> None:
        self.query_one("#input-source", Input).focus()
    
    # --- GESTION KEYRING (Copie de encrypt_file.py) ---
    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "select-auth-mode": return
        manual_mode = event.value == "mode-manual"
        if manual_mode:
            self.query_one("#container-manual").remove_class("hidden")
            self.query_one("#container-key").remove_class("visible")
        else:
            self.query_one("#container-manual").add_class("hidden")
            self.query_one("#container-key").add_class("visible")
            self._load_keys()
    
    def _get_keyring(self):
        shared = getattr(self.app, "shared_keyring", None)
        if shared and not shared.is_locked: return shared
        from ...core.keyring import Keyring
        return Keyring()

    def _load_keys(self) -> None:
        try:
            keyring = self._get_keyring()
            select = self.query_one("#select-key", Select)
            status = self.query_one("#key-status", Label)
            
            if not keyring.exists:
                status.update("⚠ No keyring found.")
                select.disabled = True
                return
            if keyring.is_locked:
                status.update("🔒 Keyring is locked.")
                select.disabled = True
                self._keyring_unlocked = False
                return
            
            self._keyring_unlocked = True
            select.disabled = False
            status.update("")
            keys = keyring.list_keys()
            options = [(f"{k.name} ({k.algorithm.name})", k.key_id) for k in keys]
            if not options: status.update("⚠ Keyring is empty.")
            select.set_options(options)
        except Exception as e:
            self.query_one("#key-status", Label).update(f"Error: {e}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel": self.action_go_back()
        elif event.button.id == "btn-encrypt": self._start_encryption()
    
    def action_go_back(self) -> None:
        if self._worker and self._worker.is_running: self._worker.cancel()
        self.app.pop_screen()
    
    # --- LOGIQUE DE VALIDATION ---
    def _validate_paths(self) -> Optional[str]:
        """Valide uniquement les chemins (pas le mot de passe)."""
        src = self.query_one("#input-source", Input).value.strip()
        dst = self.query_one("#input-dest", Input).value.strip()
        if not src: return "Please enter source folder path"
        if not Path(src).is_dir(): return f"Source folder not found: {src}"
        if not dst: return "Please enter output folder path"
        if Path(src).resolve() == Path(dst).resolve(): return "Output folder cannot be the same as source."
        return None

    def _get_password(self) -> Optional[str]:
        """Récupère le mot de passe (Manuel) ou la Clé (Keyring)."""
        val = self.query_one("#select-auth-mode", Select).value
        if val is None: return None
        is_manual = val == "mode-manual"
        
        if is_manual:
            pw = self.query_one("#input-password", Input).value
            confirm = self.query_one("#input-confirm", Input).value
            if not pw: self._show_status("Please enter a password", is_error=True); return None
            if len(pw) < 12: self._show_status("Password too short", is_error=True); return None
            if pw != confirm: self._show_status("Passwords do not match", is_error=True); return None
            return pw
        else:
            if not self._keyring_unlocked:
                self._show_status("Keyring is locked!", is_error=True); return None
            target_id = self.query_one("#select-key", Select).value
            if not target_id: self._show_status("Please select a key", is_error=True); return None
            
            try:
                keyring = self._get_keyring()
                found_key = None
                for k in keyring.list_keys():
                    if str(k.key_id) == str(target_id):
                        found_key = k; break
                
                if not found_key: raise Exception("Key ID not found")
                
                # Mise à jour compteur utilisation
                keyring.increment_use(found_key.key_id)
                return found_key.secret_value if hasattr(found_key, 'secret_value') else found_key.name
            except Exception as e:
                self._show_status(f"Key Error: {e}", is_error=True); return None

    def _start_encryption(self) -> None:
        path_error = self._validate_paths()
        if path_error:
            self._show_status(path_error, is_error=True)
            return
        
        password = self._get_password()
        if not password: return
        
        # Récupération des autres champs
        src = self.query_one("#input-source", Input).value.strip()
        dst = self.query_one("#input-dest", Input).value.strip()
        algo = self.query_one("#select-algo", Select).value
        include = self.query_one("#input-include", Input).value.strip()
        exclude = self.query_one("#input-exclude", Input).value.strip()
        recursive = self.query_one("#check-recursive", Checkbox).value
        dry_run = self.query_one("#check-dryrun", Checkbox).value
        continue_on_error = self.query_one("#check-continue", Checkbox).value
        
        self.query_one("#progress-log").add_class("visible")
        self.query_one("#progress-log", Log).clear()
        self._show_status("Processing..." if not dry_run else "Preview mode...", is_error=False)
        
        self._worker = self._do_encrypt(src, dst, password, algo, include, exclude, 
                                      recursive, dry_run, continue_on_error)
    
    @work(thread=True, name="encrypt_folder")
    def _do_encrypt(self, src: str, dst: str, password: str,
                    algo: str, include: str, exclude: str,
                    recursive: bool, dry_run: bool, 
                    continue_on_error: bool) -> None:
        from ...core import Algorithm, OperationType
        from ...core.vault import SecureVault
        from ...core.batch import BatchProcessor
        from ...core.io_utils import FileFilter
        from ...core.audit import AuditLogger
        
        start_time = time.time()
        
        try:
            algorithm = Algorithm.CHACHA20_POLY1305 if algo == "chacha" else Algorithm.AES_256_GCM
            vault = SecureVault(algorithm=algorithm)
            
            include_patterns = [p.strip() for p in include.split(',') if p.strip()] if include else None
            exclude_patterns = [p.strip() for p in exclude.split(',') if p.strip()] if exclude else None
            file_filter = FileFilter(include_patterns=include_patterns, exclude_patterns=exclude_patterns)
            
            processor = BatchProcessor(vault, file_filter)
            
            def progress_callback(progress):
                msg = f"[{progress.processed_files}/{progress.total_files}] {progress.current_file or ''}"
                self.app.call_from_thread(self._log_progress, msg)
                if progress.total_files > 0:
                    pct = int(progress.processed_files / progress.total_files * 100)
                    self.app.call_from_thread(self._update_bar, pct)
            
            result = processor.encrypt_folder(
                Path(src), Path(dst), password,
                recursive=recursive,
                dry_run=dry_run,
                continue_on_error=continue_on_error,
                progress_callback=progress_callback
            )
            
            # Audit Log
            if not dry_run:
                duration = int((time.time() - start_time) * 1000)
                try:
                    logger = AuditLogger()
                    status = "success" if result.failed_files == 0 else "warning"
                    logger.log_operation(
                        operation=OperationType.ENCRYPT_FOLDER,
                        src_path=src, dst_path=dst, status=status,
                        algorithm=algorithm.name, duration_ms=duration,
                        file_count=result.succeeded_files + result.failed_files,
                        error_message=f"{result.failed_files} failed" if result.failed_files > 0 else None
                    )
                except Exception: pass
            
            self.app.call_from_thread(self._on_success, result, dry_run)
            
        except Exception as e:
            # Audit Crash
            try:
                duration = int((time.time() - start_time) * 1000)
                logger = AuditLogger()
                logger.log_operation(
                    operation=OperationType.ENCRYPT_FOLDER, src_path=src,
                    status="failed", duration_ms=duration, error_message=str(e)
                )
            except Exception: pass
            self.app.call_from_thread(self._on_error, str(e))
    
    def _log_progress(self, msg: str) -> None:
        self.query_one("#progress-log", Log).write_line(msg)
    
    def _update_bar(self, pct: int) -> None:
        self.query_one("#progress-bar", ProgressBar).update(progress=pct)
    
    def _on_success(self, result, dry_run: bool) -> None:
        prefix = "[DRY RUN] " if dry_run else ""
        msg = f"{prefix}Complete! {result.succeeded_files} succeeded, {result.failed_files} failed"
        self._show_status(f"✓ {msg}", is_error=False)
        if result.errors:
            for path, error in result.errors[:5]:
                self._log_progress(f"ERROR: {Path(path).name}: {error}")
        
        # Clear fields
        self.query_one("#input-password", Input).value = ""
        self.query_one("#input-confirm", Input).value = ""
    
    def _on_error(self, error: str) -> None:
        self._show_status(f"Error: {error}", is_error=True)
    
    def _show_status(self, message: str, is_error: bool) -> None:
        label = self.query_one("#status-label", Label)
        label.update(message)
        label.remove_class("success", "error")
        if message: label.add_class("error" if is_error else "success")