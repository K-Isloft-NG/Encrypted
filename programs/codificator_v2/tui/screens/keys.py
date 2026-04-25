"""
Key Management screen.

Manage encryption keys stored in the local keyring.
"""

from typing import Optional
import secrets

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Input, DataTable
from textual.binding import Binding


class KeysScreen(Screen):
    """Screen for managing encryption keys."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("n", "new_key", "New Key"),
        Binding("delete", "delete_key", "Delete"),
    ]
    
    CSS = """
    KeysScreen {
        align: center middle;
    }
    
    #main-container {
        width: 90;
        height: 90%;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
    }
    
    #keys-list {
        height: 1fr;
        border: solid $secondary;
        margin: 1 0;
    }
    
    #action-row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    
    #action-row Button {
        margin: 0 1;
    }
    
    #status-label {
        text-align: center;
        margin: 1 0;
    }
    
    .error { color: $error; }
    .success { color: $success; }
    
    #unlock-container {
        width: 60;
        height: auto;
        border: thick $warning;
        padding: 2 4;
        background: $surface-lighten-1;
        align: center middle;
    }
    
    #unlock-container.hidden {
        display: none;
    }
    
    #lock-message {
        width: 100%;
        text-align: center;
        margin-bottom: 2;
        text-style: bold;
    }
    
    #input-master {
        width: 100%;
        margin-bottom: 2;
    }
    
    #auth-buttons {
        width: 100%;
        align: center middle;
        height: auto;
    }
    
    #keys-container {
        display: none;
    }
    
    #keys-container.visible {
        display: block;
        height: 1fr;
    }
    """
    
    def __init__(self):
        super().__init__()
        self._keyring = None
        self._unlocked = False
    
    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            yield Static("═══ KEY MANAGEMENT ═══", id="title")
            
            # Zone de déverrouillage
            with Container(id="unlock-container"):
                yield Label("Initializing...", id="lock-message")
                yield Input(placeholder="Master password...", password=True, id="input-master")
                with Horizontal(id="auth-buttons"):
                    yield Button("Unlock", id="btn-unlock", variant="primary")
                    yield Button("Create Vault", id="btn-create-keyring", variant="success")
            
            # Zone de gestion des clés
            with Container(id="keys-container"):
                yield DataTable(id="keys-table")
                with Horizontal(id="action-row"):
                    yield Button("New Key [N]", id="btn-new", variant="primary")
                    yield Button("Delete", id="btn-delete", variant="error")
                    yield Button("Lock", id="btn-lock", variant="warning")
            
            yield Label("", id="status-label")
            with Horizontal():
                yield Button("Back", id="btn-back", variant="default")
    
    def on_mount(self) -> None:
        table = self.query_one("#keys-table", DataTable)
        table.add_columns("ID", "Name", "Algorithm", "Created", "Uses")
        table.cursor_type = "row"
        self._check_keyring()
    
    def _check_keyring(self) -> None:
        """Check shared keyring status first, then disk status."""
        
        # [MODIFICATION] Vérifie si le trousseau est déjà partagé dans l'app
        shared = getattr(self.app, "shared_keyring", None)
        if shared and not shared.is_locked:
            self._keyring = shared
            self._unlocked = True
            self._show_interface_unlocked()
            self._refresh_keys()
            return

        # Sinon, on charge une nouvelle instance
        from ...core.keyring import Keyring
        self._keyring = Keyring()
        
        label = self.query_one("#lock-message", Label)
        btn_unlock = self.query_one("#btn-unlock", Button)
        btn_create = self.query_one("#btn-create-keyring", Button)
        inp_master = self.query_one("#input-master", Input)
        
        if self._keyring.exists:
            label.update("🔒 Keyring is locked.\nEnter master password:")
            btn_unlock.display = True
            btn_create.display = False
            inp_master.focus()
        else:
            label.update("🆕 No keyring found.\nCreate a Master Password to initialize:")
            btn_unlock.display = False
            btn_create.display = True
            inp_master.display = True
            inp_master.focus()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-back": self.action_go_back()
        elif bid == "btn-unlock": self._unlock_keyring()
        elif bid == "btn-create-keyring": self._create_keyring()
        elif bid == "btn-lock": self._lock_keyring()
        elif bid == "btn-new": self._new_key()
        elif bid == "btn-delete": self._delete_key()
    
    def action_go_back(self) -> None:
        self.app.pop_screen()
    
    def action_new_key(self) -> None:
        if self._unlocked: self._new_key()
    
    def action_delete_key(self) -> None:
        if self._unlocked: self._delete_key()
    
    def _unlock_keyring(self) -> None:
        password = self.query_one("#input-master", Input).value
        if not password:
            self._show_status("Please enter master password", is_error=True)
            return
        
        try:
            self._keyring.unlock(password)
            self._unlocked = True
            
            # [MODIFICATION] Partage le trousseau déverrouillé avec toute l'app
            setattr(self.app, "shared_keyring", self._keyring)
            
            self._show_interface_unlocked()
            self._refresh_keys()
            self._show_status("Keyring unlocked", is_error=False)
            self.query_one("#input-master", Input).value = ""
        except Exception as e:
            self._show_status(f"Failed to unlock: {e}", is_error=True)
    
    def _create_keyring(self) -> None:
        password = self.query_one("#input-master", Input).value
        if len(password) < 4:
            self._show_status("Password too short", is_error=True)
            return
        
        try:
            self._keyring.create(password)
            self._unlocked = True
            
            # [MODIFICATION] Partage le trousseau créé
            setattr(self.app, "shared_keyring", self._keyring)
            
            self._show_interface_unlocked()
            self._refresh_keys()
            self._show_status("Keyring created successfully!", is_error=False)
            self.query_one("#input-master", Input).value = ""
        except Exception as e:
            self._show_status(f"Failed to create keyring: {e}", is_error=True)
            
    def _show_interface_unlocked(self):
        self.query_one("#unlock-container").add_class("hidden")
        self.query_one("#keys-container").add_class("visible")
        self.query_one("#keys-container").remove_class("hidden")
    
    def _lock_keyring(self) -> None:
        if self._keyring:
            self._keyring.lock()
        self._unlocked = False
        
        # [MODIFICATION] Supprime le partage
        setattr(self.app, "shared_keyring", None)
        
        self.query_one("#unlock-container").remove_class("hidden")
        self.query_one("#keys-container").remove_class("visible")
        self.query_one("#input-master", Input).value = ""
        self._show_status("Keyring locked", is_error=False)
        self._check_keyring()
    
    def _refresh_keys(self) -> None:
        if not self._unlocked: return
        table = self.query_one("#keys-table", DataTable)
        table.clear()
        try:
            keys = self._keyring.list_keys()
            for key in keys:
                short_id = key.key_id[:8] + "..."
                created = key.created_at[:10] if key.created_at else "-"
                table.add_row(
                    short_id,
                    key.name,
                    key.algorithm.name if hasattr(key.algorithm, 'name') else str(key.algorithm),
                    created,
                    str(key.use_count),
                    key=key.key_id
                )
        except Exception as e:
            self._show_status(f"Error loading keys: {e}", is_error=True)
    
    def _new_key(self) -> None:
        name = f"Project_Key_{secrets.token_hex(2).upper()}"
        try:
            self._keyring.create_key(name)
            self._refresh_keys()
            self._show_status(f"Created new key: {name}", is_error=False)
        except Exception as e:
            self._show_status(f"Error creating key: {e}", is_error=True)
    
    def _delete_key(self) -> None:
        table = self.query_one("#keys-table", DataTable)
        if table.cursor_row is None:
            self._show_status("Select a key to delete", is_error=True)
            return
        try:
            full_keys = self._keyring.list_keys()
            target_key = full_keys[table.cursor_row]
            self._keyring.delete_key(target_key.key_id)
            self._refresh_keys()
            self._show_status(f"Deleted key: {target_key.name}", is_error=False)
        except Exception as e:
            self._show_status(f"Error deleting key: {e}", is_error=True)
    
    def _show_status(self, message: str, is_error: bool) -> None:
        label = self.query_one("#status-label", Label)
        label.update(message)
        label.remove_class("success", "error")
        if message:
            label.add_class("error" if is_error else "success")