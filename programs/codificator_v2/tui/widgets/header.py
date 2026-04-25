"""
Header widget for Codificator TUI.

Displays application title, status, and current settings.
"""

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static
from textual.reactive import reactive


class Header(Widget):
    """Application header widget."""
    
    DEFAULT_CSS = """
    Header {
        dock: top;
        height: 3;
        background: $primary-darken-2;
        color: $text;
    }
    
    Header > Static {
        width: 100%;
        text-align: center;
        padding: 1;
    }
    
    Header .title {
        text-style: bold;
    }
    
    Header .status {
        color: $text-muted;
    }
    """
    
    profile: reactive[str] = reactive("PERSONAL")
    algorithm: reactive[str] = reactive("AES-256-GCM")
    
    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id="header-content")
    
    def _render_header(self) -> str:
        return f"╔═ CODIFICATOR V2 ═╗  [{self.profile}]  Algorithm: {self.algorithm}"
    
    def watch_profile(self, value: str) -> None:
        self.query_one("#header-content", Static).update(self._render_header())
    
    def watch_algorithm(self, value: str) -> None:
        self.query_one("#header-content", Static).update(self._render_header())
