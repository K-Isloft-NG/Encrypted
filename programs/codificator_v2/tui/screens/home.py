"""
Home screen for Codificator TUI.

Main menu with navigation to all features.
"""

from textual.app import ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Static, Button, Label
from textual.binding import Binding


# Ton logo ASCII original
LOGO = """
╔═══════════════════════════════════════════════════════════════╗
║   ██████╗ ██████╗ ██████╗ ██╗███████╗██╗ ██████╗ █████╗       ║
║  ██╔════╝██╔═══██╗██╔══██╗██║██╔════╝██║██╔════╝██╔══██╗      ║
║  ██║     ██║   ██║██║  ██║██║█████╗  ██║██║     ███████║      ║
║  ██║     ██║   ██║██║  ██║██║██╔══╝  ██║██║     ██╔══██║      ║
║  ╚██████╗╚██████╔╝██████╔╝██║██║     ██║╚██████╗██║  ██║      ║
║   ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝      ║
║                    ╔╦╗╔═╗╦═╗  V2                              ║
║                     ║ ║ ║╠╦╝  Enterprise Lite                 ║
║                     ╩ ╚═╝╩╚═  Secure File Encryption          ║
╚═══════════════════════════════════════════════════════════════╝
"""

# Texte d'information et légal (Panneau de droite)
INFO_TEXT = """
[b]USAGE & FONCTIONNALITÉ[/b]
Cet outil permet le chiffrement AES-256-GCM de fichiers sensibles.

[b]GUIDE RAPIDE[/b]
• [b]Encrypt/Decrypt File[/b] : Pour un fichier unique.
• [b]Batch Processing[/b] : Pour traiter tout un dossier.
• [b]Verify[/b] : Contrôler l'intégrité avant déchiffrement.

[b]AUTEUR & LICENCE[/b]
Conçu et développé par [b]NAT NGAM Karl[/b].
Logiciel propriétaire. Tous droits réservés.

[b][red]AVERTISSEMENT LÉGAL[/red][/b]
L'usage malveillant de ce logiciel est interdit.

[i]Conformément à l'Article 323-1 du Code Pénal :[/i]
"Le fait d'accéder ou de se maintenir, frauduleusement, dans tout ou partie d'un système de traitement automatisé de données est puni de deux ans d'emprisonnement et de 60 000 € d'amende."

Toute republication non autorisée est interdite.
"""

class HomeScreen(Screen):
    """Home screen with main menu."""
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("e", "encrypt_file", "Encrypt File"),
        Binding("d", "decrypt_file", "Decrypt File"),
    ]
    
    CSS = """
    HomeScreen {
        align: center middle;
        background: $surface;
    }
    
    #main-container {
        /* Largeur augmentée pour accueillir les 2 colonnes + le logo */
        width: 120;
        height: auto;
        border: thick $primary;
        padding: 0 1;
        background: $surface;
        align: center middle;
    }
    
    /* --- LE LOGO --- */
    #logo {
        text-align: center;
        color: $primary;
        margin-bottom: 1;
        width: 100%;
        height: auto;
    }
    
    /* --- ZONE CONTENU (Boutons à gauche | Texte à droite) --- */
    #content-row {
        height: auto;
        width: 100%;
        margin-bottom: 1;
    }

    /* --- COLONNE GAUCHE : MENU --- */
    #left-col {
        width: 45;
        height: auto;
        border-right: solid $secondary; /* Séparation verticale */
        align: center middle;           /* Centre les boutons dans la colonne */
        padding-right: 1;
    }

    .menu-btn {
        width: 40;            /* Largeur fixe pour l'esthétique */
        margin: 0 0 1 0;
        text-align: center;
    }
    
    #btn-quit {
        margin-top: 1;
        background: $error-darken-2;
        color: $text;
        width: 40;
    }
    
    /* --- COLONNE DROITE : INFO --- */
    #right-col {
        width: 1fr;
        height: auto;
        padding-left: 2;
        color: $text-muted;
    }
    
    #info-text {
        width: 100%;
    }

    #version-label {
        text-align: center;
        color: $text-muted;
        margin-top: 0;
        margin-bottom: 1;
        text-opacity: 60%;
        width: 100%;
    }
    """
    
    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            # 1. Le Logo ASCII
            yield Static(LOGO, id="logo")
            
            # 2. Zone principale (Split Horizontal)
            with Horizontal(id="content-row"):
                
                # Colonne Gauche : Tes boutons centrés
                with Vertical(id="left-col"):
                    yield Button("[1]Encrypt File", id="btn-encrypt-file", variant="primary", classes="menu-btn")
                    yield Button("[2]Decrypt File", id="btn-decrypt-file", variant="primary", classes="menu-btn")
                    
                    yield Button("[3]Encrypt Folder (Batch)", id="btn-encrypt-folder", variant="default", classes="menu-btn")
                    yield Button("[4]Decrypt Folder (Batch)", id="btn-decrypt-folder", variant="default", classes="menu-btn")
                    
                    yield Button("[5]Verify Integrity", id="btn-verify", variant="default", classes="menu-btn")
                    yield Button("[6]Manage Keys", id="btn-keys", variant="default", classes="menu-btn")
                    yield Button("[7]Audit Logs", id="btn-audit", variant="default", classes="menu-btn")
                    yield Button("[8]Settings", id="btn-settings", variant="default", classes="menu-btn")
                    
                    yield Button("Quit Application", id="btn-quit", classes="menu-btn")
                
                # Colonne Droite : Ton texte légal
                with Vertical(id="right-col"):
                    yield Static(INFO_TEXT, id="info-text")
            
            # 3. Version (En bas de tout)
            yield Label("v2.0.0 • Student Edition", id="version-label")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-encrypt-file":
            self.app.push_screen("encrypt_file")
        elif button_id == "btn-decrypt-file":
            self.app.push_screen("decrypt_file")
        elif button_id == "btn-encrypt-folder":
            self.app.push_screen("encrypt_folder")
        elif button_id == "btn-decrypt-folder":
            self.app.push_screen("decrypt_folder")
        elif button_id == "btn-verify":
            self.app.push_screen("verify")
        elif button_id == "btn-keys":
            self.app.push_screen("keys")
        elif button_id == "btn-settings":
            self.app.push_screen("settings")
        elif button_id == "btn-audit":
            self.app.push_screen("audit")
        elif button_id == "btn-quit":
            self.app.exit()
    
    def action_quit(self) -> None:
        self.app.exit()
    
    def action_encrypt_file(self) -> None:
        self.app.push_screen("encrypt_file")
    
    def action_decrypt_file(self) -> None:
        self.app.push_screen("decrypt_file")
    
    def action_encrypt_folder(self) -> None:
        self.app.push_screen("encrypt_folder")
    
    def action_decrypt_folder(self) -> None:
        self.app.push_screen("decrypt_folder")
    
    def action_verify(self) -> None:
        self.app.push_screen("verify")