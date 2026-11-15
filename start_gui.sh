#!/usr/bin/env bash
# PLC Discovery（GUI）を起動します。
# 初回は仮想環境の作成とパッケージのインストールを行います。
set -u
cd "$(dirname "$0")" || exit 1
source scripts/setup_env.sh
setup_env --gui || exit 1

if ! "$VENV_PY" -c "import tkinter" 2>/dev/null; then
    echo "[エラー] Tkinter（画面表示の部品）を含む Python 3.10 以降が見つかりません。" >&2
    echo "  macOS (Homebrew): brew install python-tk" >&2
    echo "  Debian/Ubuntu:    sudo apt install python3-tk" >&2
    echo "  インストール後にもう一度実行すると、自動でその Python を使います。" >&2
    exit 1
fi

exec "$VENV_PY" plc_gui.py
