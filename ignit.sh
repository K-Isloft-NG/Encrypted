#!/bin/bash

# ====================================================
#  LAUNCHER POUR CODIFICATOR V2
#  Se place dans le dossier du script pour garantir
#  que les chemins relatifs fonctionnent.
#  Utilise l'environnement virtuel du projet (.venv)
# ====================================================

# 1. Se déplacer à l'emplacement exact de ce script
cd "$(dirname "$0")"

# 2. Vérifier que l'environnement virtuel existe
if [ ! -d ".venv" ]; then
    echo "[ERREUR] Environnement virtuel introuvable (.venv)."
    echo "Créez-le avec : python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    echo
    read -rp "Appuyez sur Entrée pour fermer..."
    exit 1
fi

# 3. Informer l'utilisateur
echo "Lancement de Codificator V2..."
echo

# 4. Lancer le script Python via l'environnement virtuel
.venv/bin/python3 "programs/codificator_v2.py"

# 5. Si le programme plante ou se termine, on affiche l'erreur
if [ $? -ne 0 ]; then
    echo
    echo "[ERREUR] Le programme s'est arrêté de manière inattendue."
    echo "Vérifiez que l'environnement virtuel est correctement configuré."
    echo "Essayez : .venv/bin/pip install -r requirements.txt"
fi

echo
read -rp "Appuyez sur Entrée pour fermer..."
