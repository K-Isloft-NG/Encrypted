"""
Footer widget for Codificator TUI.

Displays keyboard shortcuts and hints.
"""

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static


class Footer(Widget):
    """Application footer widget with shortcuts."""
    
    DEFAULT_CSS = """
    Footer {
        dock: bottom;
        height: 1;
        background: $primary-darken-3;
        color: $text-muted;
    }
    
    Footer > Static {
        width: 100%;
        text-align: center;
    }
    
    Footer .key {
        color: $primary-lighten-2;
        text-style: bold;
    }
    """
    
    def compose(self) -> ComposeResult:
        shortcuts = (
            "[F1] Help  "
            "[ESC] Back  "
            "[↑↓] Navigate  "
            "[ENTER] Select  "
            "[Q] Quit"
        )
        yield Static(shortcuts, id="footer-content")
    
    def set_shortcuts(self, shortcuts: str) -> None:
        """Update the displayed shortcuts."""
        self.query_one("#footer-content", Static).update(shortcuts)
