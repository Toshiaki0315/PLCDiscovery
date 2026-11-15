#!/usr/bin/env bash
# PLC Scanner（コマンドライン版）
#
# 使い方の例:
#   ./plc_scanner.sh --mode discover --ip-range 192.168.1.0/24
#   ./plc_scanner.sh --mode range --target 192.168.1.10 --device D --range 0-99
#
# 引数なしで実行するとヘルプを表示します（誤ってネットワーク探索を始めないため）。
# 相対パスの引数（--config など）は、実行したフォルダーを基準に解釈されます。
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/scripts/setup_env.sh"
setup_env || exit 1

if [ $# -eq 0 ]; then
    exec "$VENV_PY" "$SCRIPT_DIR/plc_scanner.py" --help
fi
exec "$VENV_PY" "$SCRIPT_DIR/plc_scanner.py" "$@"
