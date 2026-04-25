"""
Textual TUI application for Codificator V2.

Features:
- Multi-page navigation with arrow keys
- Guided encryption/decryption workflows
- Key management interface
- Progress tracking
- Audit log viewer
"""

from __future__ import annotations

from typing import Optional

# Check for textual availability
try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
    from textual.screen import Screen
    from textual.widgets import (
        Header, Footer, Static, Button, Input, Label,
        ListItem, ListView, DataTable, ProgressBar,
        Select, Switch, TabbedContent, TabPane
    )
    from textual.message import Message
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


from ..version import __version__, PROGRAM_NAME
from ..core import Algorithm, ProfileType
from ..core.policies import get_config


def check_textual_available() -> bool:
    """Check if Textual is available."""
    return TEXTUAL_AVAILABLE


if TEXTUAL_AVAILABLE:
    from rich.text import Text
    
    # Import screens
    from .screens.home import HomeScreen
    from .screens.encrypt_file import EncryptFileScreen
    from .screens.decrypt_file import DecryptFileScreen
    from .screens.encrypt_folder import EncryptFolderScreen
    from .screens.decrypt_folder import DecryptFolderScreen
    from .screens.verify import VerifyScreen
    from .screens.keys import KeysScreen
    from .screens.settings import SettingsScreen
    from .screens.migration import MigrationScreen
    from .screens.audit_viewer import AuditViewerScreen


    class CodificatorApp(App):
        """
        Main Codificator TUI application.
        
        Navigation:
        - Arrow keys to navigate menus
        - Enter to select
        - Escape to go back
        - F1 for help
        - Ctrl+Q to quit
        """
        
        TITLE = PROGRAM_NAME
        SUB_TITLE = f"v{__version__} - Enterprise Lite Encryption"
        
        # Register all screens
        SCREENS = {
            "home": HomeScreen,
            "encrypt_file": EncryptFileScreen,
            "decrypt_file": DecryptFileScreen,
            "encrypt_folder": EncryptFolderScreen,
            "decrypt_folder": DecryptFolderScreen,
            "verify": VerifyScreen,
            "keys": KeysScreen,
            "settings": SettingsScreen,
            "migration": MigrationScreen,
            "audit": AuditViewerScreen,
        }
        
        CSS = """
        Screen {
            background: $surface;
        }
        
        #header {
            dock: top;
            height: 3;
            background: $primary;
            color: $text;
            text-align: center;
            padding: 1;
        }
        
        #status-bar {
            dock: top;
            height: 1;
            background: $primary-darken-2;
            color: $text-muted;
            padding: 0 1;
        }
        
        .menu-container {
            width: 100%;
            height: auto;
            padding: 1 2;
        }
        
        .menu-item {
            width: 100%;
            height: 3;
            margin: 0 0 1 0;
            padding: 1 2;
            background: $surface-lighten-1;
            border: solid $primary;
        }
        
        .menu-item:hover {
            background: $primary-darken-1;
        }
        
        .menu-item:focus {
            background: $primary;
            border: double $secondary;
        }
        
        .section-title {
            text-style: bold;
            color: $primary;
            padding: 1 0;
        }
        
        .warning {
            color: $warning;
        }
        
        .error {
            color: $error;
        }
        
        .success {
            color: $success;
        }
        
        .info-box {
            border: solid $primary;
            padding: 1;
            margin: 1;
        }
        
        Input {
            margin: 1 0;
        }
        
        Button {
            margin: 1 1 1 0;
        }
        
        ProgressBar {
            margin: 1 0;
        }
        
        #wizard-container {
            width: 100%;
            height: auto;
            padding: 2;
        }
        
        .wizard-step {
            margin: 1 0;
            padding: 1;
            border: solid $surface-lighten-2;
        }
        
        .wizard-step-active {
            border: double $primary;
            background: $surface-lighten-1;
        }
        """
        
        BINDINGS = [
            Binding("ctrl+q", "quit", "Quit", show=True),
            Binding("f1", "help", "Help", show=True),
            Binding("escape", "back", "Back", show=True),
            Binding("f5", "refresh", "Refresh", show=False),
        ]
        
        def __init__(self):
            super().__init__()
            self.config = get_config()
        
        def compose(self) -> ComposeResult:
            """Create main app layout."""
            yield Header()
            yield Footer()
        
        def on_mount(self) -> None:
            """Called when app is mounted."""
            # Push home screen (using registered screen name)
            self.push_screen("home")
        
        async def action_quit(self) -> None:
            """Quit the application."""
            self.exit()
        
        async def action_back(self) -> None:
            """Go back to previous screen."""
            if len(self.screen_stack) > 1:
                self.pop_screen()
        
        def action_help(self) -> None:
            """Show help."""
            self.notify("Help: Use arrow keys to navigate, Enter to select, Escape to go back")
        
        def action_refresh(self) -> None:
            """Refresh current screen."""
            self.notify("Refreshed")
        
        def navigate_to(self, screen_name: str) -> None:
            """Navigate to a screen by name."""
            screens = {
                "home": HomeScreen,
                "encrypt_file": EncryptFileScreen,
                "decrypt_file": DecryptFileScreen,
                "encrypt_folder": EncryptFolderScreen,
                "decrypt_folder": DecryptFolderScreen,
                "verify": VerifyScreen,
                "keys": KeysScreen,
                "settings": SettingsScreen,
                "migration": MigrationScreen,
                "audit": AuditViewerScreen,
            }
            
            screen_class = screens.get(screen_name)
            if screen_class:
                self.push_screen(screen_class())
            else:
                self.notify(f"Unknown screen: {screen_name}", severity="error")


    def run_tui() -> int:
        """Run the TUI application."""
        if not TEXTUAL_AVAILABLE:
            print("Error: Textual library not installed.")
            print("Install with: pip install textual")
            return 1
        
        app = CodificatorApp()
        app.run()
        return 0


else:
    # Stub when textual not available
    def run_tui() -> int:
        print("Error: Textual library not installed.")
        print("Install with: pip install textual")
        return 1
