#!/usr/bin/env python3
"""
PLC Scanner GUI - PLC自動探索・データ収集ツールのグラフィカル画面

標準ライブラリの Tkinter のみで動作します（追加インストール不要）。
通信処理はバックグラウンドスレッドの asyncio ループで実行するため、
スキャン中も画面が固まりません。

起動方法:
    python plc_gui.py

安全設計:
    - 読み取り専用（書き込み機能はありません）
    - パケット間隔・タイムアウトは「通信設定」タブで調整
    - フルスキャン開始時は工場停止中であることを確認するダイアログを表示
"""

import asyncio
import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Dict, List, Optional

from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import (
    PROTOCOL_PORTS,
    DataPoint,
    DeviceType,
    NetworkConfig,
    PLCInfo,
    Protocol,
    StatusCode,
)
from plc_discovery.data_types import ByteOrder
from plc_discovery.discovery import PLCDiscovery, discover_plcs
from plc_discovery.output import DEFAULT_OUTPUT_DIR, CSVExporter
from plc_scanner import BYTE_ORDER_MAP, DATA_TYPE_MAP, apply_data_type_conversion

APP_TITLE = "PLC Discovery - PLC自動探索・データ収集ツール"

# Treeview に表示する最大行数（全件は CSV に保存される）
MAX_DISPLAY_ROWS = 5000

# 周期実行の最小間隔（秒）: 生産中のPLCに負荷をかけないための下限
MIN_PERIODIC_INTERVAL_SEC = 1.0

PROTOCOL_CHOICES = ["自動検出"] + [p.name for p in Protocol]

STATUS_LABELS = {
    StatusCode.OK: "OK",
    StatusCode.NG_ILLEGAL_ADDR: "NG: 無効アドレス",
    StatusCode.NG_TIMEOUT: "NG: タイムアウト",
    StatusCode.NG_COMM_ERROR: "NG: 通信エラー",
    StatusCode.NG_UNSUPPORTED: "NG: 非対応",
}

BYTE_ORDER_LABELS = {
    "little": "リトル CDAB（下位ワード先頭・標準）",
    "big": "ビッグ ABCD（上位ワード先頭）",
    "little_swap": "リトル + バイトスワップ DCBA",
    "big_swap": "ビッグ + バイトスワップ BADC",
}


# ---------------------------------------------------------------------------
# バックグラウンド処理（通信用ワーカー）
# ---------------------------------------------------------------------------


class AsyncWorker:
    """専用スレッドで asyncio ループを回し、GUI スレッドからジョブを投入する"""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True, name="plc-worker")
        self._thread.start()
        self._future: Optional["asyncio.Future"] = None

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    @property
    def busy(self) -> bool:
        return self._future is not None and not self._future.done()

    def submit(self, coro, on_done: Callable[[Optional[BaseException]], None]) -> None:
        """コルーチンを投入する。完了時に on_done(例外 or None) をワーカースレッドで呼ぶ"""
        self._future = asyncio.run_coroutine_threadsafe(coro, self.loop)

        def _done(fut) -> None:
            if fut.cancelled():
                on_done(asyncio.CancelledError())
            else:
                on_done(fut.exception())

        self._future.add_done_callback(_done)

    def cancel(self) -> None:
        if self.busy:
            self._future.cancel()

    def shutdown(self) -> None:
        self.cancel()
        self.loop.call_soon_threadsafe(self.loop.stop)


class QueueLogHandler(logging.Handler):
    """ログレコードを GUI キューへ流す"""

    def __init__(self, q: "queue.Queue") -> None:
        super().__init__()
        self.q = q
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.q.put(("log", record.levelname, self.format(record)))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# メイン画面
# ---------------------------------------------------------------------------


class PLCScannerApp:
    """PLC探索・データ収集ツールのメイン画面"""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1080x760")
        self.root.minsize(900, 620)

        self.ui_queue: "queue.Queue" = queue.Queue()
        self.worker = AsyncWorker()
        self.discovered: List[PLCInfo] = []
        self.last_output_dir: Optional[Path] = None

        logging.getLogger().addHandler(QueueLogHandler(self.ui_queue))
        logging.getLogger().setLevel(logging.INFO)

        self._init_vars()
        self._build_style()
        self._build_layout()
        self._on_mode_change()
        self._on_discover_scope_change()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._poll_queue)

    # ----- 画面の状態（入力値など） ----------------------------------

    def _init_vars(self) -> None:
        # PLC探索タブ
        self.var_scope = tk.StringVar(value="segment")
        self.var_ip_range = tk.StringVar(value="192.168.1.0/24")
        self.var_broadcast = tk.BooleanVar(value=True)

        # データ収集タブ
        self.var_target = tk.StringVar()
        self.var_protocol = tk.StringVar(value=PROTOCOL_CHOICES[0])
        self.var_port = tk.StringVar()
        self.var_mode = tk.StringVar(value="range")
        self.var_device = tk.StringVar(value=DeviceType.D.value)
        self.var_start = tk.StringVar(value="0")
        self.var_end = tk.StringVar(value="99")
        self.var_periodic = tk.BooleanVar(value=False)
        self.var_interval = tk.StringVar(value="60")
        self.var_data_type = tk.StringVar(value="(変換なし)")
        self.var_byte_order = tk.StringVar(value=BYTE_ORDER_LABELS["little"])
        self.var_ng_only = tk.BooleanVar(value=False)

        # 通信・出力設定タブ
        self.var_packet_interval = tk.StringVar(value="50")
        self.var_retry_interval = tk.StringVar(value="200")
        self.var_timeout = tk.StringVar(value="5000")
        self.var_output_dir = tk.StringVar(value=str(Path(DEFAULT_OUTPUT_DIR).resolve()))
        self.var_encoding = tk.StringVar(value="utf-8")

        # ステータス表示
        self.var_status = tk.StringVar(value="準備完了")
        self.var_summary = tk.StringVar(value="")

        self._last_points: List[DataPoint] = []

    # ----- 画面レイアウト ---------------------------------------

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        if sys.platform.startswith("win") and "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names() and sys.platform != "darwin":
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("", 13, "bold"))
        style.configure("Hint.TLabel", foreground="#666666")
        style.configure("Primary.TButton", font=("", 11, "bold"), padding=(14, 6))
        style.configure("Treeview", rowheight=22)

    def _build_layout(self) -> None:
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)

        paned = ttk.PanedWindow(outer, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(paned)
        paned.add(self.notebook, weight=4)

        self.tab_discover = ttk.Frame(self.notebook, padding=10)
        self.tab_collect = ttk.Frame(self.notebook, padding=10)
        self.tab_settings = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_discover, text="  ① PLC探索  ")
        self.notebook.add(self.tab_collect, text="  ② データ収集  ")
        self.notebook.add(self.tab_settings, text="  ③ 通信・出力設定  ")

        self._build_discover_tab()
        self._build_collect_tab()
        self._build_settings_tab()

        # ログ表示エリア
        log_frame = ttk.LabelFrame(paned, text="ログ", padding=6)
        paned.add(log_frame, weight=1)
        self.log_text = tk.Text(log_frame, height=7, wrap=tk.NONE, state=tk.DISABLED, font=("Menlo", 10)
                                if sys.platform == "darwin" else ("Consolas", 9))
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.tag_configure("WARNING", foreground="#b26a00")
        self.log_text.tag_configure("ERROR", foreground="#c62828")

        # ステータスバー（進捗バー・停止ボタン）
        status = ttk.Frame(outer, padding=(0, 6, 0, 0))
        status.pack(fill=tk.X)
        self.progress = ttk.Progressbar(status, mode="determinate", length=260)
        self.progress.pack(side=tk.LEFT)
        ttk.Label(status, textvariable=self.var_status).pack(side=tk.LEFT, padx=10)
        self.btn_stop = ttk.Button(status, text="■ 停止", command=self._stop, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.RIGHT)
        ttk.Button(status, text="出力フォルダを開く", command=self._open_output_dir).pack(side=tk.RIGHT, padx=6)

    def _build_discover_tab(self) -> None:
        f = self.tab_discover
        ttk.Label(f, text="ネットワーク上のPLCを探します", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            f,
            text="SLMP / EtherNet/IP / Modbus/TCP / S7 / FINS のポートに問い合わせ、応答したPLCを一覧表示します。",
            style="Hint.TLabel",
        ).pack(anchor=tk.W, pady=(0, 8))

        opts = ttk.LabelFrame(f, text="探索範囲", padding=8)
        opts.pack(fill=tk.X)
        ttk.Radiobutton(opts, text="同じネットワーク（自動）", value="segment", variable=self.var_scope,
                        command=self._on_discover_scope_change).grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(opts, text="IP範囲を指定:", value="range", variable=self.var_scope,
                        command=self._on_discover_scope_change).grid(row=0, column=1, sticky=tk.W, padx=(20, 4))
        self.ent_ip_range = ttk.Entry(opts, textvariable=self.var_ip_range, width=26)
        self.ent_ip_range.grid(row=0, column=2, sticky=tk.W)
        ttk.Label(opts, text="例: 192.168.1.0/24  または  192.168.1.10-192.168.1.50",
                  style="Hint.TLabel").grid(row=1, column=2, sticky=tk.W)
        ttk.Checkbutton(opts, text="UDPブロードキャスト探索も行う", variable=self.var_broadcast).grid(
            row=1, column=0, sticky=tk.W, pady=(4, 0))

        btns = ttk.Frame(f)
        btns.pack(fill=tk.X, pady=8)
        self.btn_discover = ttk.Button(btns, text="▶ 探索開始", style="Primary.TButton", command=self._start_discovery)
        self.btn_discover.pack(side=tk.LEFT)
        self.btn_to_collect = ttk.Button(btns, text="選択したPLCのデータを収集 →", command=self._use_selected_plc,
                                         state=tk.DISABLED)
        self.btn_to_collect.pack(side=tk.LEFT, padx=10)
        self.lbl_discover_count = ttk.Label(btns, text="")
        self.lbl_discover_count.pack(side=tk.RIGHT)

        cols = ("ip", "manufacturer", "model", "protocol", "port", "mac")
        headings = ("IPアドレス", "メーカー", "機種", "プロトコル", "ポート", "MACアドレス")
        widths = (140, 140, 180, 120, 70, 150)
        self.tree_plc = self._make_tree(f, cols, headings, widths)
        self.tree_plc.bind("<<TreeviewSelect>>", lambda e: self.btn_to_collect.configure(
            state=tk.NORMAL if self.tree_plc.selection() else tk.DISABLED))
        self.tree_plc.bind("<Double-1>", lambda e: self._use_selected_plc())
        ttk.Label(f, text="ヒント: 行をダブルクリックすると、そのPLCを「データ収集」タブに設定します。",
                  style="Hint.TLabel").pack(anchor=tk.W, pady=(4, 0))

    def _build_collect_tab(self) -> None:
        f = self.tab_collect
        top = ttk.Frame(f)
        top.pack(fill=tk.X)

        # 接続先PLC
        tgt = ttk.LabelFrame(top, text="接続先PLC", padding=8)
        tgt.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 8))
        ttk.Label(tgt, text="IPアドレス").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(tgt, textvariable=self.var_target, width=18).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Label(tgt, text="プロトコル").grid(row=1, column=0, sticky=tk.W)
        cb_proto = ttk.Combobox(tgt, textvariable=self.var_protocol, values=PROTOCOL_CHOICES,
                                state="readonly", width=16)
        cb_proto.grid(row=1, column=1, sticky=tk.W, pady=2)
        cb_proto.bind("<<ComboboxSelected>>", self._on_protocol_change)
        ttk.Label(tgt, text="ポート").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(tgt, textvariable=self.var_port, width=8).grid(row=2, column=1, sticky=tk.W, pady=2)
        ttk.Label(tgt, text="空欄=標準ポート", style="Hint.TLabel").grid(row=3, column=1, sticky=tk.W)

        # 収集モード
        mode = ttk.LabelFrame(top, text="収集モード", padding=8)
        mode.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        ttk.Radiobutton(mode, text="範囲指定（生産中でも可）", value="range", variable=self.var_mode,
                        command=self._on_mode_change).grid(row=0, column=0, columnspan=4, sticky=tk.W)
        ttk.Label(mode, text="デバイス").grid(row=1, column=0, sticky=tk.W, padx=(20, 4))
        self.cb_device = ttk.Combobox(mode, textvariable=self.var_device, values=[d.value for d in DeviceType],
                                      state="readonly", width=5)
        self.cb_device.grid(row=1, column=1, sticky=tk.W)
        ttk.Label(mode, text="アドレス").grid(row=1, column=2, sticky=tk.W, padx=(10, 4))
        rng = ttk.Frame(mode)
        rng.grid(row=1, column=3, sticky=tk.W)
        self.ent_start = ttk.Entry(rng, textvariable=self.var_start, width=7)
        self.ent_start.pack(side=tk.LEFT)
        ttk.Label(rng, text=" 〜 ").pack(side=tk.LEFT)
        self.ent_end = ttk.Entry(rng, textvariable=self.var_end, width=7)
        self.ent_end.pack(side=tk.LEFT)

        per = ttk.Frame(mode)
        per.grid(row=2, column=0, columnspan=4, sticky=tk.W, padx=(20, 0), pady=(4, 0))
        self.chk_periodic = ttk.Checkbutton(per, text="周期実行:", variable=self.var_periodic,
                                            command=self._on_mode_change)
        self.chk_periodic.pack(side=tk.LEFT)
        self.ent_interval = ttk.Entry(per, textvariable=self.var_interval, width=6)
        self.ent_interval.pack(side=tk.LEFT)
        ttk.Label(per, text="秒ごと（停止ボタンで終了）").pack(side=tk.LEFT)

        ttk.Radiobutton(mode, text="フルスキャン（工場停止時のみ推奨）", value="full", variable=self.var_mode,
                        command=self._on_mode_change).grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=(8, 0))
        ttk.Label(mode, text="プロトコルごとの全デバイス範囲を読み取ります。時間がかかります。",
                  style="Hint.TLabel").grid(row=4, column=0, columnspan=4, sticky=tk.W, padx=(20, 0))

        # データ型変換
        dt = ttk.LabelFrame(top, text="データ型変換（任意）", padding=8)
        dt.pack(side=tk.LEFT, fill=tk.BOTH)
        ttk.Label(dt, text="データ型").grid(row=0, column=0, sticky=tk.W)
        ttk.Combobox(dt, textvariable=self.var_data_type, values=["(変換なし)"] + list(DATA_TYPE_MAP.keys()),
                     state="readonly", width=12).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Label(dt, text="バイト順").grid(row=1, column=0, sticky=tk.W)
        ttk.Combobox(dt, textvariable=self.var_byte_order, values=list(BYTE_ORDER_LABELS.values()),
                     state="readonly", width=20).grid(row=1, column=1, sticky=tk.W, pady=2)

        # 操作ボタン
        act = ttk.Frame(f)
        act.pack(fill=tk.X, pady=8)
        self.btn_collect = ttk.Button(act, text="▶ 収集開始", style="Primary.TButton", command=self._start_collect)
        self.btn_collect.pack(side=tk.LEFT)
        ttk.Label(act, text="※ 読み取り専用です。PLCへの書き込みは一切行いません。",
                  style="Hint.TLabel").pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(act, text="NGのみ表示", variable=self.var_ng_only,
                        command=self._refresh_data_tree).pack(side=tk.RIGHT)
        ttk.Label(act, textvariable=self.var_summary).pack(side=tk.RIGHT, padx=10)

        cols = ("address", "value", "hex", "converted", "status", "timestamp")
        headings = ("アドレス", "値 (10進)", "値 (16進)", "変換値", "ステータス", "取得時刻")
        widths = (100, 100, 90, 160, 150, 180)
        self.tree_data = self._make_tree(f, cols, headings, widths)
        self.tree_data.tag_configure("ng", background="#fdecea", foreground="#b71c1c")

    def _build_settings_tab(self) -> None:
        f = self.tab_settings
        net = ttk.LabelFrame(f, text="通信設定（PLCへの負荷を抑えるための待ち時間）", padding=10)
        net.pack(fill=tk.X)
        rows = [
            ("パケット送信間隔", self.var_packet_interval, "ミリ秒", "読み取り要求の間に入れる待ち時間（標準 50）"),
            ("リトライ待機時間", self.var_retry_interval, "ミリ秒", "エラー時に再試行するまでの待ち時間（標準 200）"),
            ("タイムアウト", self.var_timeout, "ミリ秒", "応答を待つ最大時間（標準 5000）"),
        ]
        for i, (label, var, unit, hint) in enumerate(rows):
            ttk.Label(net, text=label, width=16).grid(row=i, column=0, sticky=tk.W, pady=3)
            ttk.Entry(net, textvariable=var, width=8).grid(row=i, column=1, sticky=tk.W)
            ttk.Label(net, text=unit).grid(row=i, column=2, sticky=tk.W, padx=4)
            ttk.Label(net, text=hint, style="Hint.TLabel").grid(row=i, column=3, sticky=tk.W, padx=10)
        ttk.Button(net, text="標準値に戻す", command=self._reset_network_defaults).grid(
            row=len(rows), column=0, sticky=tk.W, pady=(8, 0))

        out = ttk.LabelFrame(f, text="出力設定（CSVファイル）", padding=10)
        out.pack(fill=tk.X, pady=10)
        ttk.Label(out, text="保存先フォルダ", width=16).grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(out, textvariable=self.var_output_dir, width=60).grid(row=0, column=1, sticky=tk.W)
        ttk.Button(out, text="参照...", command=self._browse_output_dir).grid(row=0, column=2, padx=6)
        ttk.Label(out, text="文字コード", width=16).grid(row=1, column=0, sticky=tk.W, pady=(6, 0))
        enc = ttk.Frame(out)
        enc.grid(row=1, column=1, sticky=tk.W, pady=(6, 0))
        ttk.Radiobutton(enc, text="UTF-8", value="utf-8", variable=self.var_encoding).pack(side=tk.LEFT)
        ttk.Radiobutton(enc, text="Shift-JIS（Excelで直接開く場合）", value="shift_jis",
                        variable=self.var_encoding).pack(side=tk.LEFT, padx=12)

    def _make_tree(self, parent, cols, headings, widths) -> ttk.Treeview:
        """スクロールバー付きの一覧表（Treeview）を作る"""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        for c, h, w in zip(cols, headings, widths):
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor=tk.W)
        ys = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ys.pack(side=tk.RIGHT, fill=tk.Y)
        return tree

    # ----- 画面操作のイベント処理 -----------------------------------

    def _on_discover_scope_change(self) -> None:
        self.ent_ip_range.configure(state=tk.NORMAL if self.var_scope.get() == "range" else tk.DISABLED)

    def _on_mode_change(self) -> None:
        is_range = self.var_mode.get() == "range"
        st = tk.NORMAL if is_range else tk.DISABLED
        for w in (self.ent_start, self.ent_end, self.chk_periodic):
            w.configure(state=st)
        self.cb_device.configure(state="readonly" if is_range else tk.DISABLED)
        self.ent_interval.configure(state=tk.NORMAL if is_range and self.var_periodic.get() else tk.DISABLED)

    def _on_protocol_change(self, _event=None) -> None:
        name = self.var_protocol.get()
        if name in Protocol.__members__:
            self.var_port.set(str(PROTOCOL_PORTS[Protocol[name]]))
        else:
            self.var_port.set("")

    def _reset_network_defaults(self) -> None:
        d = NetworkConfig()
        self.var_packet_interval.set(str(d.packet_interval_ms))
        self.var_retry_interval.set(str(d.retry_interval_ms))
        self.var_timeout.set(str(d.request_timeout_ms))

    def _browse_output_dir(self) -> None:
        path = filedialog.askdirectory(initialdir=self.var_output_dir.get() or ".")
        if path:
            self.var_output_dir.set(path)

    def _open_output_dir(self) -> None:
        path = Path(self.var_output_dir.get())
        path.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as e:
            messagebox.showerror("エラー", f"フォルダを開けませんでした:\n{e}")

    def _use_selected_plc(self) -> None:
        """探索結果で選択したPLCを「データ収集」タブの接続先に設定する"""
        sel = self.tree_plc.selection()
        if not sel:
            return
        plc = self.discovered[int(sel[0])]
        self.var_target.set(plc.ip_address)
        if plc.protocol:
            self.var_protocol.set(plc.protocol.name)
            self.var_port.set(str(plc.port or PROTOCOL_PORTS.get(plc.protocol, "")))
        self.notebook.select(self.tab_collect)

    # ----- 入力値チェック ---------------------------------------

    def _int_field(self, var: tk.StringVar, label: str, minimum: int = 0) -> int:
        """入力欄の値を整数として取り出す。不正な値なら日本語のエラーメッセージで ValueError"""
        try:
            v = int(var.get().strip())
        except ValueError:
            raise ValueError(f"「{label}」には整数を入力してください。")
        if v < minimum:
            raise ValueError(f"「{label}」は {minimum} 以上にしてください。")
        return v

    def _network_config(self) -> NetworkConfig:
        return NetworkConfig(
            packet_interval_ms=self._int_field(self.var_packet_interval, "パケット送信間隔"),
            retry_interval_ms=self._int_field(self.var_retry_interval, "リトライ待機時間"),
            request_timeout_ms=self._int_field(self.var_timeout, "タイムアウト", minimum=100),
            max_concurrent=1,
        )

    def _exporter(self) -> CSVExporter:
        out = self.var_output_dir.get().strip() or DEFAULT_OUTPUT_DIR
        return CSVExporter(out, self.var_encoding.get())

    # ----- 処理の実行・停止 --------------------------------------

    def _set_busy(self, busy: bool, message: str = "") -> None:
        st = tk.DISABLED if busy else tk.NORMAL
        self.btn_discover.configure(state=st)
        self.btn_collect.configure(state=st)
        self.btn_stop.configure(state=tk.NORMAL if busy else tk.DISABLED)
        if busy:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)
        if message:
            self.var_status.set(message)

    def _run_job(self, coro, start_msg: str) -> None:
        """通信処理をワーカーに投入し、実行中はボタンを無効化する（同時実行は1件のみ）"""
        if self.worker.busy:
            messagebox.showinfo("実行中", "別の処理が実行中です。完了するか停止してから実行してください。")
            return
        self._set_busy(True, start_msg)
        self.worker.submit(coro, lambda exc: self.ui_queue.put(("done", exc)))

    def _stop(self) -> None:
        self.var_status.set("停止しています...")
        self.worker.cancel()

    def _progress_cb(self, message: str, current: int, total: int) -> None:
        """ワーカースレッドから呼ばれる進捗コールバック"""
        self.ui_queue.put(("progress", message, current, total))

    def _post(self, *item) -> None:
        self.ui_queue.put(item)

    # ----- PLC探索 -----------------------------------------

    def _start_discovery(self) -> None:
        try:
            config = self._network_config()
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return
        ip_range = self.var_ip_range.get().strip() if self.var_scope.get() == "range" else None
        if self.var_scope.get() == "range" and not ip_range:
            messagebox.showwarning("入力エラー", "IP範囲を入力してください。")
            return
        self.tree_plc.delete(*self.tree_plc.get_children())
        self.discovered = []
        self.lbl_discover_count.configure(text="")
        self._run_job(self._discover_job(config, ip_range, self.var_broadcast.get(), self._exporter()),
                      "PLCを探索しています...")

    async def _discover_job(self, config: NetworkConfig, ip_range: Optional[str], use_broadcast: bool,
                            exporter: CSVExporter) -> None:
        """ブロードキャスト探索とポートスキャンでPLCを探し、結果をCSVに保存する"""
        plcs: List[PLCInfo] = []
        if use_broadcast:
            self._post("status", "UDPブロードキャストで探索中...")
            try:
                plcs.extend(await BroadcastDiscovery(config).discover_all_broadcast())
            except Exception as e:  # 失敗しても続行
                logging.warning(f"ブロードキャスト探索に失敗しました（続行します）: {e}")

        self._post("status", f"{ip_range or '同一セグメント'} をスキャン中...")
        tcp_plcs = await discover_plcs(ip_range, config, self._progress_cb)
        known = {p.ip_address for p in plcs}
        plcs.extend(p for p in tcp_plcs if p.ip_address not in known)

        path = exporter.export_discovery_results(plcs) if plcs else None
        self._post("discovered", plcs, path)

    def _show_discovered(self, plcs: List[PLCInfo], path: Optional[str]) -> None:
        self.discovered = plcs
        self.tree_plc.delete(*self.tree_plc.get_children())
        for i, p in enumerate(plcs):
            d = p.to_dict()
            self.tree_plc.insert("", tk.END, iid=str(i), values=(
                d["ip_address"], d["manufacturer"] or "-", d["model"] or "-",
                d["protocol"] or "-", d["port"], d["mac_address"] or "-"))
        if plcs:
            self.lbl_discover_count.configure(text=f"{len(plcs)} 台のPLCを検出")
            self.var_status.set(f"探索完了: {len(plcs)} 台検出  →  {path}")
            self.last_output_dir = Path(path).parent if path else None
        else:
            self.lbl_discover_count.configure(text="PLCは見つかりませんでした")
            self.var_status.set("探索完了: PLCは見つかりませんでした")

    # ----- データ収集 -----------------------------------------

    def _start_collect(self) -> None:
        try:
            config = self._network_config()
            ip = self.var_target.get().strip()
            if not ip:
                raise ValueError("接続先PLCのIPアドレスを入力してください。")
            proto_name = self.var_protocol.get()
            protocol = Protocol[proto_name] if proto_name in Protocol.__members__ else None
            port = self._int_field(self.var_port, "ポート", 1) if self.var_port.get().strip() else None

            mode = self.var_mode.get()
            device_type = DeviceType(self.var_device.get())
            start = self._int_field(self.var_start, "開始アドレス")
            end = self._int_field(self.var_end, "終了アドレス")
            if mode == "range" and end < start:
                raise ValueError("終了アドレスは開始アドレス以上にしてください。")
            interval = 0.0
            if mode == "range" and self.var_periodic.get():
                try:
                    interval = float(self.var_interval.get())
                except ValueError:
                    raise ValueError("「周期」には数値（秒）を入力してください。")
                if interval < MIN_PERIODIC_INTERVAL_SEC:
                    raise ValueError(f"周期は {MIN_PERIODIC_INTERVAL_SEC:g} 秒以上にしてください（PLC負荷対策）。")
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return

        if mode == "full" and not messagebox.askyesno(
            "フルスキャンの確認",
            "フルスキャンは全デバイス範囲を読み取るため、通信量が多く時間がかかります。\n\n"
            "工場停止中（メンテナンス時）での実行を推奨します。\n生産中の場合は「範囲指定」モードを使ってください。\n\n"
            "フルスキャンを開始しますか？",
            icon=messagebox.WARNING,
        ):
            return

        dt_name = self.var_data_type.get()
        data_type = DATA_TYPE_MAP.get(dt_name)
        bo_key = next((k for k, v in BYTE_ORDER_LABELS.items() if v == self.var_byte_order.get()), "little")
        byte_order = BYTE_ORDER_MAP.get(bo_key, ByteOrder.LITTLE_ENDIAN)

        self._last_points = []
        self._refresh_data_tree()
        self.var_summary.set("")
        self._run_job(
            self._collect_job(config, ip, protocol, port, mode, device_type, start, end, interval,
                              data_type, byte_order, self._exporter()),
            f"{ip} に接続しています...",
        )

    async def _collect_job(self, config, ip, protocol, port, mode, device_type, start, end, interval,
                           data_type, byte_order, exporter: CSVExporter) -> None:
        """指定PLCに接続してデータを読み取り、CSVに保存する（周期実行時は停止まで繰り返す）"""
        # プロトコル決定（自動検出または手動指定）
        if protocol is None:
            self._post("status", f"{ip} のプロトコルを自動検出中...")
            detected = await PLCDiscovery(config)._probe_host(ip)
            if detected and detected.protocol:
                plc = detected
                if port:
                    plc.port = port
                logging.info(f"プロトコルを検出しました: {plc.protocol.name}")
            else:
                raise RuntimeError(
                    f"{ip} のプロトコルを検出できませんでした。\n"
                    "PLCの電源・ネットワーク接続を確認するか、プロトコルを手動で選択してください。")
        else:
            plc = PLCInfo(ip_address=ip, protocol=protocol, port=port or PROTOCOL_PORTS.get(protocol))

        collector = PLCDataCollector(plc, config)
        collector.set_progress_callback(self._progress_cb)
        if not await collector.connect():
            raise RuntimeError(f"{ip}:{plc.port} ({plc.protocol.name}) に接続できませんでした。")
        exported_denied: set = set()
        loop = asyncio.get_running_loop()
        try:
            iteration = 0
            while True:
                iteration += 1
                started = loop.time()
                if mode == "full":
                    points = await collector.collect_full_scan()
                else:
                    if interval:
                        self._post("status", f"周期実行 {iteration} 回目: 読み取り中...")
                    collector.clear_data()
                    points = await collector.collect_range(device_type, start, end)

                if data_type:
                    points = apply_data_type_conversion(points, data_type, byte_order, None)

                path = exporter.export_plc_data(points, ip) if points else None
                # Append only addresses not yet logged (avoid duplicates every cycle)
                new_denied = collector.get_denied_addresses() - exported_denied
                denied_path = exporter.export_denied_addresses(new_denied, ip) if new_denied else None
                exported_denied |= new_denied
                self._post("data", points, collector.get_statistics(), path, denied_path, iteration)

                if not interval:
                    break
                # Fixed period: subtract the time spent reading
                wait = max(0.0, interval - (loop.time() - started))
                self._post("status", f"周期実行 {iteration} 回目完了。{wait:.1f} 秒後に次回実行（停止ボタンで終了）")
                await asyncio.sleep(wait)
        finally:
            await collector.disconnect()

    def _show_data(self, points: List[DataPoint], stats: Dict, path: Optional[str], denied_path: Optional[str],
                   iteration: int) -> None:
        self._last_points = points
        self._refresh_data_tree()
        ok = stats.get("success_count", 0)
        total = stats.get("total_points", 0)
        self.var_summary.set(f"全 {total} 件   OK {ok} 件   NG {total - ok} 件   成功率 {stats.get('success_rate')}")
        prefix = f"[{iteration}回目] " if iteration > 1 or self.var_periodic.get() else ""
        if path:
            self.last_output_dir = Path(path).parent
            self.var_status.set(f"{prefix}収集完了 → {path}")
        else:
            self.var_status.set(f"{prefix}収集完了（データなし）")
        if denied_path:
            logging.info(f"アクセス不可アドレスを記録しました: {denied_path}")

    def _refresh_data_tree(self) -> None:
        """収集結果を一覧表に表示する（NGのみ表示・最大表示件数を反映）"""
        tree = self.tree_data
        tree.delete(*tree.get_children())
        points = self._last_points
        if self.var_ng_only.get():
            points = [p for p in points if p.status != StatusCode.OK]
        for i, p in enumerate(points[:MAX_DISPLAY_ROWS]):
            ng = p.status != StatusCode.OK
            tree.insert("", tk.END, iid=str(i), tags=("ng",) if ng else (), values=(
                p.address,
                "" if p.value is None else p.value,
                p.raw_hex or "",
                p.display_value or ("" if p.converted_value is None else p.converted_value),
                STATUS_LABELS.get(p.status, p.status.value),
                p.timestamp,
            ))
        if len(points) > MAX_DISPLAY_ROWS:
            tree.insert("", tk.END, iid="more", values=(
                f"… 他 {len(points) - MAX_DISPLAY_ROWS} 件", "", "", "全件はCSVファイルに保存されています", "", ""))

    # ----- キュー処理（GUIスレッドで画面を更新） --------------------------

    def _poll_queue(self) -> None:
        """ワーカーからの通知を100msごとに取り出して画面に反映する"""
        try:
            while True:
                item = self.ui_queue.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._append_log(item[1], item[2])
                elif kind == "status":
                    self.var_status.set(item[1])
                elif kind == "progress":
                    _, msg, cur, total = item
                    self.var_status.set(msg)
                    if total:
                        self.progress.stop()
                        self.progress.configure(mode="determinate", maximum=total, value=cur)
                elif kind == "discovered":
                    self._show_discovered(item[1], item[2])
                elif kind == "data":
                    self._show_data(*item[1:])
                elif kind == "done":
                    self._on_job_done(item[1])
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _on_job_done(self, exc: Optional[BaseException]) -> None:
        """処理の終了（正常・停止・エラー）を画面に反映する"""
        current = self.var_status.get()
        self._set_busy(False)
        if isinstance(exc, asyncio.CancelledError):
            self.var_status.set("停止しました（完了した収集分のみCSVに保存されています）")
            logging.info("ユーザー操作により停止しました")
        elif exc is not None:
            self.var_status.set("エラーで終了しました")
            logging.error(str(exc))
            messagebox.showerror("エラー", str(exc))
        else:
            self.var_status.set(current)

    def _append_log(self, level: str, text: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, text + "\n", level)
        # ログが肥大化しないよう古い行を削除
        lines = int(self.log_text.index("end-1c").split(".")[0])
        if lines > 2000:
            self.log_text.delete("1.0", f"{lines - 2000}.0")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        """ウィンドウを閉じる。実行中なら確認してから停止する"""
        if self.worker.busy and not messagebox.askyesno("終了確認", "処理を実行中です。停止して終了しますか？"):
            return
        self.worker.shutdown()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    PLCScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
