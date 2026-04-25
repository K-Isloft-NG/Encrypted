# CODIFICATOR V2

**Enterprise Lite File Encryption System**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Educational-green.svg)]()

---

## Overview

**Codificator V2** is a professional-grade file encryption system designed for secure local data protection.  
It provides strong authenticated encryption, batch processing, key management, audit logging, and both CLI and TUI interfaces.

### Key Features

- 🔐 **AEAD Encryption**
  - AES-256-GCM (default)
  - ChaCha20-Poly1305
- 🔑 **Key Management**
  - Local encrypted keyring
  - Import / export encrypted keys
- 📁 **Batch Operations**
  - Folder encryption & decryption
  - Filters, recursion, parallel jobs
- 🖥️ **Dual Interface**
  - Modern TUI (Textual)
  - Full-featured CLI
- 📋 **Audit Logging**
  - JSONL logs
  - Paranoid mode support
- 🔄 **Migration**
  - V1 → V2 container upgrade

---

## Installation

### Requirements

- Python **3.11+**
- Linux (Ubuntu) / Windows / macOS

### Setup (environnement virtuel)

```bash
# 1. Cloner le projet puis se placer dans le dossier
cd codificatorv2

# 2. Créer l'environnement virtuel
python3 -m venv .venv

# 3. Activer l'environnement virtuel
source .venv/bin/activate

# 4. Installer les dépendances
pip install -r requirements.txt
```

### Dependencies

| Package        | Version | Rôle                          |
| -------------- | ------- | ----------------------------- |
| cryptography   | 46.0+   | AES-GCM, ChaCha20, scrypt    |
| textual        | 7.5+    | Interface TUI moderne         |
| rich           | 14.3+   | Rendu terminal (via textual)  |

---

## Quick Start

### Lancer l'application (TUI)

```bash
./ignit.sh
```

Ou manuellement :

```bash
source .venv/bin/activate
python3 programs/codificator_v2.py
```

**Navigation TUI :**

- Flèches ↑↓ → naviguer
- Entrée → sélectionner
- Échap → retour

---

## CLI Usage

### 1. Chiffrer un fichier

```bash
python3 -m codificator_v2 encrypt-file \
  --in secret.txt \
  --out secret.codi \
  --password-prompt
```

### 2. Déchiffrer un fichier

```bash
python3 -m codificator_v2 decrypt-file \
  --in secret.codi \
  --out decrypted.txt \
  --password-prompt
```

### 3. Chiffrer un dossier

```bash
python3 -m codificator_v2 encrypt-folder \
  --in ./documents \
  --out ./encrypted \
  --password-prompt \
  --recursive
```

### 4. Inspecter un fichier chiffré

```bash
python3 -m codificator_v2 info --in secret.codi
```

### 5. Algorithmes de chiffrement

| Algorithme        | Description            | Cas d'usage     |
| ----------------- | ---------------------- | --------------- |
| AES-256-GCM       | Standard industriel    | Par défaut      |
| ChaCha20-Poly1305 | Chiffrement par flux   | Si pas d'AES-NI |

---

## Container Formats

### V1 (Compatible)

- Magic : `CODI`
- Pas de compression
- Compatible avec Codificator V0

### V2 (Recommandé)

- Magic : `CDI2`
- Compression zlib optionnelle
- Nonces dérivés
- Métadonnées améliorées

---

## Key Management

```bash
python3 -m codificator_v2 keys list
python3 -m codificator_v2 keys create --name "work-key"
python3 -m codificator_v2 keys export --name "work-key" --out key.export
python3 -m codificator_v2 keys import --file key.export --name "imported-key"
```

---

## Batch Operations

```bash
python3 -m codificator_v2 encrypt-folder \
  --in ./data \
  --out ./encrypted \
  --password-prompt \
  --include "*.txt,*.json" \
  --exclude "node_modules,*.tmp" \
  --recursive \
  --jobs 4
```

### Dry Run

```bash
python3 -m codificator_v2 encrypt-folder \
  --in ./data \
  --out ./encrypted \
  --password-prompt \
  --dry-run
```

---

## Migration (V1 → V2)

```bash
python3 -m codificator_v2 migrate \
  --in old.codi \
  --out new.codi \
  --password-prompt \
  --compress
```

---

## Configuration

Fichier de configuration : `~/.codificator_config.json`

```json
{
  "profile": "personal",
  "algorithm": "aes",
  "container_version": 2,
  "compression": false,
  "scrypt_n": 32768,
  "min_password_length": 12,
  "audit_enabled": true,
  "paranoid_mode": false,
  "max_workers": 4
}
```

---

## Security Notes

### Best Practices

- Utiliser des mots de passe de **16+ caractères**
- Activer les **logs d'audit**
- Utiliser le **mode paranoïaque** pour les données sensibles
- Combiner **mot de passe + keyfile** pour du 2FA

### Garanties

- ✅ Confidentialité & intégrité (AEAD)
- ✅ Résistance au brute-force (scrypt)
- ✅ Écritures atomiques
- ✅ Détection de falsification

### Limitations

- ❌ Keyloggers
- ❌ OS compromis
- ❌ Analyse forensique mémoire
- ❌ Attaques post-quantiques

---

## Project Structure

```
codificatorv2/
├── ignit.sh                  # Launcher Linux (lance le TUI via .venv)
├── requirements.txt          # Dépendances Python
├── .venv/                    # Environnement virtuel Python
├── ico/
│   └── favicon.ico           # Icône de l'application
└── programs/
    ├── codificator_v2.py     # Point d'entrée principal
    └── codificator_v2/       # Package Python
        ├── __init__.py       # Package init
        ├── __main__.py       # Entry point (-m)
        ├── version.py        # Version info
        ├── core/             # Logique métier (pas d'UI)
        │   ├── __init__.py   # Types, constantes
        │   ├── errors.py     # Classes d'exceptions
        │   ├── crypto_aead.py# AES-GCM, ChaCha20
        │   ├── kdf.py        # scrypt, politique de mot de passe
        │   ├── container_v1.py # Format V1
        │   ├── container_v2.py # Format V2
        │   ├── vault.py      # API de chiffrement principale
        │   ├── keyring.py    # Gestion des clés
        │   ├── batch.py      # Opérations par lot
        │   ├── migrate.py    # Migration V1→V2
        │   ├── audit.py      # Logs JSONL
        │   ├── policies.py   # Config & profils
        │   └── io_utils.py   # Utilitaires fichiers
        ├── cli/              # Interface ligne de commande
        │   └── __init__.py   # Commandes argparse
        ├── tui/              # Interface Textual
        │   ├── __init__.py   # Classe App
        │   ├── screens/      # Pages TUI
        │   └── widgets/      # Widgets personnalisés
        └── tests/            # Suite de tests
            └── test_all.py
```

---

## Development

```bash
# Activer le venv
source .venv/bin/activate

# Lancer les tests
python3 -m pytest programs/tests/ -v
python3 -m codificator_v2 --self-test
```

---

## License

Educational and authorized enterprise use only.

---

## Changelog

### V2.0.0

- Refonte complète de l'architecture
- Interface TUI basée sur Textual
- Format de conteneur V2
- Keyring chiffré
- Chiffrement par lot
- Logs d'audit
- Migration V1 → V2

### V1.0.0

- Vault sécurisé initial
- AES-GCM & ChaCha20
- CLI basique
