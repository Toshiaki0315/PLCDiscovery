#!/usr/bin/env bash
# ============================================================
#  PLC シミュレータ（SLMP / Modbus / EtherNet/IP / S7 / FINS）を起動します。
#  止めるときは Ctrl+C を押してください。
#
#  待ち受けアドレスは 127.0.0.1（このPCからのみ接続可）です。
#  他のPCから接続したい場合: ./start_simulators.sh --host 0.0.0.0
#  ※工場のネットワーク上では、本物のPLCと紛らわしいため 0.0.0.0 にしないでください。
#
#  ポート: SLMP 5001 / Modbus 1502 / EtherNet/IP 44818（SLC形式）・44819（Logix形式）・44820（オムロン NJ/NX 形式） / S7 1102 / FINS 9600(UDP,TCP)
#  シミュレータは標準ライブラリだけで動くため、パッケージのインストールは不要です。
# ============================================================
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/scripts/setup_env.sh"   # _find_python / VENV_PY を使う（インストールはしない）

if [ -x "$VENV_PY" ]; then
    PY="$VENV_PY"
elif ! PY="$(_find_python 0)"; then
    echo "[エラー] Python 3.10 以降が見つかりません。インストールしてから再実行してください。" >&2
    exit 1
fi

echo "シミュレータを起動しています。止めるときは Ctrl+C を押してください。"
echo
# 利用者の --host 指定は後ろに付くので、既定の 127.0.0.1 より優先される
"$PY" "$SCRIPT_DIR/simulators/run_all.py" --host 127.0.0.1 "$@"
status=$?
# 130 = Ctrl+C で終了
if [ $status -ne 0 ] && [ $status -ne 130 ]; then
    echo "シミュレータの起動に失敗しました。ポートが他のプログラムで使われていないか確認してください。" >&2
fi
exit $status
