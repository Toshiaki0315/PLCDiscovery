#!/usr/bin/env bash
# ============================================================
#  PLC Discovery 実行環境のセットアップ
#  （start_gui.sh / plc_scanner.sh から source されます）
#
#   1. Python 3.10 以降を探す（GUI 用は Tkinter を含む Python を優先）
#   2. 初回のみ .venv（仮想環境）を作成する
#      （GUI 用で .venv に Tkinter がなければ、Tkinter のある Python で作り直す）
#   3. requirements.txt が変わったときだけパッケージをインストールする
#
#  setup_env が成功すると VENV_PY に仮想環境の python を設定します。
# ============================================================

PLCD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLCD_VENV="$PLCD_ROOT/.venv"
VENV_PY="$PLCD_VENV/bin/python"
PLCD_STAMP="$PLCD_VENV/requirements.installed"

_python_candidates() {
    # PATH 上の名前に加えて、Homebrew / python.org の既定の場所も探す
    local v
    echo python3
    for v in 15 14 13 12 11 10; do
        echo "python3.$v"
        echo "/opt/homebrew/bin/python3.$v"
        echo "/usr/local/bin/python3.$v"
        echo "/Library/Frameworks/Python.framework/Versions/3.$v/bin/python3"
    done
    echo python
}

_is_usable_python() {  # $1 = python, $2 = 1 if Tkinter is required
    command -v "$1" >/dev/null 2>&1 || return 1
    "$1" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null || return 1
    [ "$2" = 1 ] || return 0
    "$1" -c 'import tkinter' 2>/dev/null
}

_find_python() {  # $1 = 1 to prefer a Python that includes Tkinter (GUI)
    local candidate
    if [ "${1:-0}" = 1 ]; then
        while read -r candidate; do
            if _is_usable_python "$candidate" 1; then echo "$candidate"; return 0; fi
        done < <(_python_candidates)
    fi
    while read -r candidate; do
        if _is_usable_python "$candidate" 0; then echo "$candidate"; return 0; fi
    done < <(_python_candidates)
    return 1
}

setup_env() {  # setup_env [--gui]
    local need_tk=0 base
    [ "${1:-}" = "--gui" ] && need_tk=1

    # GUI 用: 既存の仮想環境に Tkinter がなく、Tkinter のある Python が
    # 見つかれば、その Python で仮想環境を作り直す
    if [ "$need_tk" = 1 ] && [ -x "$VENV_PY" ] && ! "$VENV_PY" -c 'import tkinter' 2>/dev/null; then
        while read -r base; do
            if _is_usable_python "$base" 1; then
                echo "Tkinter のある Python ($base) で仮想環境を作り直します..."
                rm -rf "$PLCD_VENV"
                break
            fi
        done < <(_python_candidates)
    fi

    if [ ! -x "$VENV_PY" ]; then
        if ! base="$(_find_python "$need_tk")"; then
            echo "[エラー] Python 3.10 以降が見つかりません。インストールしてから再実行してください。" >&2
            return 1
        fi
        echo "仮想環境を作成しています... ($base)"
        if ! "$base" -m venv "$PLCD_VENV"; then
            echo "[エラー] 仮想環境の作成に失敗しました。" >&2
            echo "  Debian/Ubuntu では python3-venv パッケージが必要です。" >&2
            return 1
        fi
    fi

    # requirements.txt がインストール済みのものと同じなら何もしない
    if ! cmp -s "$PLCD_ROOT/requirements.txt" "$PLCD_STAMP"; then
        echo "依存パッケージをインストールしています。数分かかることがあります..."
        "$VENV_PY" -m pip install --disable-pip-version-check -q --upgrade pip >/dev/null 2>&1
        if ! "$VENV_PY" -m pip install --disable-pip-version-check -r "$PLCD_ROOT/requirements.txt"; then
            if [ -f "$PLCD_STAMP" ]; then
                # 以前のインストールは成功している（オフラインの工場PCで requirements.txt が
                # 更新された場合など）: 起動できなくするより、入っているパッケージで動かす
                echo "[警告] パッケージを更新できませんでした。以前にインストールしたパッケージで起動します。" >&2
                echo "  インターネットに接続できるときに、もう一度起動すると更新されます。" >&2
                return 0
            fi
            echo "[エラー] パッケージのインストールに失敗しました。" >&2
            echo "  インターネット接続やプロキシの設定を確認してから、もう一度実行してください。" >&2
            return 1
        fi
        echo "任意パッケージのインストールを試しています..."
        if ! "$VENV_PY" -m pip install --disable-pip-version-check -q \
                -r "$PLCD_ROOT/requirements-optional.txt" >/dev/null 2>&1; then
            echo "  ※ netifaces は入りませんでした。サブネットを /24 とみなして探索します。動作に支障はありません。"
        fi
        cp "$PLCD_ROOT/requirements.txt" "$PLCD_STAMP"
        echo "セットアップが完了しました。"
    fi
}
