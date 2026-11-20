#!/usr/bin/env bash
# ============================================================
#  PLC シミュレータの GUI を起動します。
#  シミュレータの起動・停止、スキャナーが読む値の書き換え・自動変化、ログの確認ができます。
#
#  待ち受けアドレスは 127.0.0.1（このPCからのみ接続可）です。画面で変更できます。
#  ※工場のネットワーク上では、本物のPLCと紛らわしいため 0.0.0.0 にしないでください。
#  標準ライブラリ（Tkinter を含む）だけで動くため、パッケージのインストールは不要です。
# ============================================================
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/scripts/setup_env.sh"   # _find_python / VENV_PY を使う（インストールはしない）

if [ -x "$VENV_PY" ] && "$VENV_PY" -c 'import tkinter' 2>/dev/null; then
    PY="$VENV_PY"
elif ! PY="$(_find_python 1)" || ! "$PY" -c 'import tkinter' 2>/dev/null; then
    echo "[エラー] Tkinter（画面表示の部品）を含む Python 3.10 以降が見つかりません。" >&2
    echo "  macOS (Homebrew): brew install python-tk" >&2
    echo "  Debian/Ubuntu:    sudo apt install python3-tk" >&2
    exit 1
fi

exec "$PY" "$SCRIPT_DIR/simulators/simulator_gui.py" "$@"
