"""
Audit Log Viewer screen.

View and filter audit log events.
"""

from datetime import datetime
from typing import List, Dict

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Select, DataTable
from textual.binding import Binding


class AuditViewerScreen(Screen):
    """Screen for viewing audit logs."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("r", "refresh", "Refresh"),
    ]
    
    CSS = """
    AuditViewerScreen {
        align: center middle;
    }
    
    #main-container {
        width: 95%;
        height: 90%;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
    }
    
    /* [CORRECTION CSS] Mise en page flexible et aérée */
    #filter-row {
        height: auto;          /* Laisse la hauteur s'adapter au contenu */
        width: 100%;
        align: center middle;  /* Centre verticalement */
        padding: 1 1;          /* 1 ligne d'espace haut/bas pour éviter l'écrasement */
        margin-bottom: 1;
        border-bottom: solid $secondary 50%; /* Optionnel: petite ligne de séparation */
    }
    
    #filter-row Select {
        margin: 0 1;
        min-height: 3;         /* Force la hauteur standard */
        height: auto;
    }
    
    #filter-row Button {
        margin: 0 1;
        min-height: 3;         /* Force la même hauteur que les Select */
        height: auto;
    }
    
    #events-table {
        height: 1fr;
        border: solid $secondary;
    }
    
    #detail-container {
        height: 10;
        border: solid $secondary;
        margin: 1 0;
        padding: 1;
        overflow-y: auto;
    }
    
    #button-row {
        height: 3;
        align: center middle;
    }
    
    #button-row Button {
        margin: 0 1;
    }
    
    #status-label {
        text-align: center;
    }
    
    .error { color: $error; }
    .success { color: $success; }
    """
    
    def __init__(self):
        super().__init__()
        self._events: List[Dict] = []
    
    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            yield Static("═══ AUDIT LOG VIEWER ═══", id="title")
            
            with Horizontal(id="filter-row"):
                yield Label("Filter:")
                yield Select(
                    [
                        ("All Operations", "all"),
                        ("Encrypt File", "encrypt_file"),
                        ("Decrypt File", "decrypt_file"),
                        ("Encrypt Folder", "encrypt_folder"),
                        ("Decrypt Folder", "decrypt_folder"),
                        ("Verify", "verify"),
                        ("Key Operations", "key"),
                    ],
                    id="select-operation",
                    value="all"
                )
                yield Select(
                    [
                        ("All Status", "all"),
                        ("Success", "success"),
                        ("Failed", "failed"),
                    ],
                    id="select-status",
                    value="all"
                )
                yield Select(
                    [
                        ("Last 50", "50"),
                        ("Last 100", "100"),
                        ("Last 500", "500"),
                    ],
                    id="select-limit",
                    value="50"
                )
                yield Button("Apply", id="btn-apply", variant="primary")
                yield Button("Refresh [R]", id="btn-refresh", variant="default")
            
            yield DataTable(id="events-table")
            
            with VerticalScroll(id="detail-container"):
                yield Static("Event Details:", id="detail-title")
                yield Label("Select an event to view details", id="detail-content")
            
            yield Label("", id="status-label")
            
            with Horizontal(id="button-row"):
                yield Button("Back", id="btn-back", variant="default")
                yield Button("Clear Log", id="btn-clear", variant="error")
                yield Button("Export", id="btn-export", variant="default")
    
    def on_mount(self) -> None:
        table = self.query_one("#events-table", DataTable)
        table.add_columns("Time", "Operation", "Status", "Source", "Algorithm")
        table.cursor_type = "row"
        self._load_events()
    
    def _load_events(self, operation: str = "all", status: str = "all", limit: int = 50) -> None:
        from ...core.audit import AuditLogger
        from ...core import OperationType
        
        try:
            logger = AuditLogger()
            
            op_filter = None
            if operation != "all":
                if operation == "key":
                    pass
                else:
                    try:
                        op_filter = OperationType(operation)
                    except:
                        pass
            
            status_filter = status if status != "all" else None
            
            self._events = logger.read_events(
                limit=limit,
                operation_filter=op_filter,
                status_filter=status_filter
            )
            
            self._refresh_table()
            self._show_status(f"Loaded {len(self._events)} events", is_error=False)
            
        except Exception as e:
            self._show_status(f"Error loading events: {e}", is_error=True)
    
    def _refresh_table(self) -> None:
        table = self.query_one("#events-table", DataTable)
        table.clear()
        
        for i, event in enumerate(self._events):
            timestamp = event.get('timestamp', '')[:19]
            operation = event.get('operation', 'unknown')
            status = event.get('status', 'unknown')
            src = event.get('src_path', '') or "-"
            
            if len(src) > 30:
                src = "..." + src[-27:]
            
            algo = event.get('algorithm', '-')
            
            if status == "success":
                status_display = "[green]✓ success[/]" 
            elif status == "failed":
                status_display = "[red]✗ failed[/]"
            else:
                status_display = status
            
            table.add_row(
                timestamp, 
                operation, 
                status_display, 
                src, 
                algo or '-', 
                key=str(i)
            )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        
        if bid == "btn-back":
            self.action_go_back()
        elif bid == "btn-apply" or bid == "btn-refresh":
            self.action_refresh()
        elif bid == "btn-clear":
            self._clear_log()
        elif bid == "btn-export":
            self._export_log()
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        try:
            if event.row_key.value is None:
                return
                
            idx = int(event.row_key.value)
            
            if 0 <= idx < len(self._events):
                event_data = self._events[idx]
                
                lines = []
                lines.append(f"[b]Timestamp:[/b] {event_data.get('timestamp', 'N/A')}")
                lines.append(f"[b]Operation:[/b] {event_data.get('operation', 'N/A')}")
                lines.append(f"[b]Status:[/b] {event_data.get('status', 'N/A')}")
                lines.append(f"[b]Source:[/b] {event_data.get('src_path', 'N/A')}")
                
                if event_data.get('dst_path'):
                    lines.append(f"[b]Dest:[/b] {event_data['dst_path']}")
                if event_data.get('algorithm'):
                    lines.append(f"[b]Algorithm:[/b] {event_data['algorithm']}")
                if event_data.get('duration_ms'):
                    lines.append(f"[b]Duration:[/b] {event_data['duration_ms']}ms")
                if event_data.get('file_count'):
                    lines.append(f"[b]Files Processed:[/b] {event_data['file_count']}")
                
                if event_data.get('error_message'):
                    lines.append("")
                    lines.append(f"[b][red]Error:[/red][/b] {event_data['error_message']}")
                
                self.query_one("#detail-content", Label).update('\n'.join(lines))
        except (ValueError, IndexError):
            self.query_one("#detail-content", Label).update("Error displaying details.")
    
    def action_go_back(self) -> None:
        self.app.pop_screen()
    
    def action_refresh(self) -> None:
        operation = str(self.query_one("#select-operation", Select).value or "all")
        status = str(self.query_one("#select-status", Select).value or "all")
        
        limit_val = self.query_one("#select-limit", Select).value
        try:
            limit = int(str(limit_val))
        except (ValueError, TypeError):
            limit = 50
            
        self._load_events(operation, status, limit)
    
    def _clear_log(self) -> None:
        try:
            from ...core.audit import AuditLogger
            logger = AuditLogger()
            logger.clear()
            self._events = []
            self._refresh_table()
            self.query_one("#detail-content", Label).update("Select an event to view details")
            self._show_status("Audit log cleared", is_error=False)
        except Exception as e:
            self._show_status(f"Error clearing log: {e}", is_error=True)
    
    def _export_log(self) -> None:
        try:
            import json
            from pathlib import Path
            
            export_path = Path.home() / f"codificator_audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(export_path, 'w') as f:
                json.dump(self._events, f, indent=2)
            
            self._show_status(f"Exported to {export_path.name}", is_error=False)
        except Exception as e:
            self._show_status(f"Export error: {e}", is_error=True)
    
    def _show_status(self, message: str, is_error: bool) -> None:
        label = self.query_one("#status-label", Label)
        label.update(message)
        label.remove_class("success", "error")
        if message:
            label.add_class("error" if is_error else "success")