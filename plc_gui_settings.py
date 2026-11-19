"""
Settings tabs of the PLC Discovery GUI: ④ notifications, ⑤ database and the
settings file shared with the CLI (③ tab, bottom). Mixed into
plc_gui.PLCScannerApp, which provides the common helpers used here
(_int_field, _network_config, _run_job, _post, var_* of tab ③).
"""

import asyncio
import math
import logging
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, Optional

from plc_discovery import settings_file
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.notifications import (
    CONFIGURABLE_EVENTS, NOTIFICATION_TYPES, NotificationEvent, NotificationManager,
    NotificationPriority, NotificationType,
)
from plc_discovery.output import DEFAULT_OUTPUT_DIR


class JobOutputs:
    """
    Notification and database outputs of one job, built from the settings
    tabs when the job starts. The database is opened in the worker thread
    (opening applies the retention limits, which may take a moment).
    """

    def __init__(self, notifier: Optional[NotificationManager], db_config: Optional[DatabaseConfig]) -> None:
        self.notifier = notifier
        self.db_config = db_config
        self.db: Optional[DatabaseExporter] = None

    def open_db(self) -> None:
        if self.db_config and self.db_config.enabled:
            try:
                self.db = DatabaseExporter(self.db_config)
            except Exception as e:
                logging.error(f"データベースを開けませんでした（CSVへの保存は続けます）: {e}")

    async def notify(self, send) -> None:
        """Send a notification if destinations are set; never stops the job"""
        if self.notifier is None or not self.notifier.has_handlers:
            return
        try:
            await send(self.notifier)
        except Exception as e:
            logging.warning(f"通知の送信に失敗しました: {e}")

    def close(self) -> None:
        if self.db:
            self.db.close()
            self.db = None


class SettingsTabsMixin:
    """④ 通知 / ⑤ データベース タブと設定ファイルの保存・読み込み"""

    def _build_notify_tab(self) -> None:
        f = self.tab_notify
        ttk.Label(f, text="スキャンの結果を Teams / Slack / Webhook に通知します", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(f, text="通知先を追加し、送る出来事（スキャン完了・エラーなど）を選んでください。"
                          "設定は「③ 通信・出力設定」の設定ファイルに保存できます。",
                  style="Hint.TLabel").pack(anchor=tk.W, pady=(0, 8))

        timing = ttk.LabelFrame(f, text="通知のタイミング", padding=8)
        timing.pack(fill=tk.X)
        ttk.Label(timing, text="定期報告の間隔", width=18).grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(timing, textvariable=self.var_report_interval, width=8).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(timing, text="分（周期実行中、各PLCの OK/NG 件数を送る。0 = 送らない）",
                  style="Hint.TLabel").grid(row=0, column=2, sticky=tk.W, padx=6)
        ttk.Label(timing, text="同じ通知の最小間隔", width=18).grid(row=1, column=0, sticky=tk.W, pady=(4, 0))
        ttk.Entry(timing, textvariable=self.var_min_interval, width=8).grid(row=1, column=1, sticky=tk.W, pady=(4, 0))
        ttk.Label(timing, text="分（この間に起きた同じ種類の通知は送らない。0 = 制限なし）",
                  style="Hint.TLabel").grid(row=1, column=2, sticky=tk.W, padx=6, pady=(4, 0))

        btns = ttk.Frame(f)
        btns.pack(fill=tk.X, pady=(10, 4))
        ttk.Button(btns, text="追加...", command=self._add_destination).pack(side=tk.LEFT)
        ttk.Button(btns, text="編集...", command=self._edit_destination).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="削除", command=self._delete_destination).pack(side=tk.LEFT)
        ttk.Button(btns, text="テスト送信", command=self._test_destination).pack(side=tk.LEFT, padx=6)

        cols = ("name", "type", "enabled", "events", "url")
        headings = ("名前", "通知方法", "有効", "通知する出来事", "URL")
        widths = (120, 80, 50, 260, 320)
        self.tree_notify = self._make_tree(f, cols, headings, widths)
        self.tree_notify.bind("<Double-1>", lambda e: self._edit_destination())

    def _refresh_notify_tree(self) -> None:
        tree = self.tree_notify
        tree.delete(*tree.get_children())
        for i, d in enumerate(self.notify_destinations):
            events = d.get("events") or []
            labels = [CONFIGURABLE_EVENTS.get(NotificationType(e), e) for e in events
                      if e in {t.value for t in NotificationType}]
            tree.insert("", tk.END, iid=str(i), values=(
                d.get("name", ""), d.get("type", "webhook"), "○" if d.get("enabled", True) else "×",
                "、".join(labels) if labels else "すべて", d.get("url", ""),
            ))

    def _selected_destination(self) -> Optional[int]:
        sel = self.tree_notify.selection()
        if not sel:
            messagebox.showinfo("通知先", "一覧から通知先を選んでください。")
            return None
        return int(sel[0])

    def _add_destination(self) -> None:
        result = self._destination_dialog(None)
        if result:
            self.notify_destinations.append(result)
            self._refresh_notify_tree()

    def _edit_destination(self) -> None:
        index = self._selected_destination()
        if index is None:
            return
        result = self._destination_dialog(self.notify_destinations[index], index)
        if result:
            self.notify_destinations[index] = result
            self._refresh_notify_tree()

    def _delete_destination(self) -> None:
        index = self._selected_destination()
        if index is None:
            return
        name = self.notify_destinations[index].get("name", "")
        if messagebox.askyesno("通知先の削除", f"通知先「{name}」を削除しますか？"):
            del self.notify_destinations[index]
            self._refresh_notify_tree()

    def _destination_dialog(self, current: Optional[Dict], index: Optional[int] = None) -> Optional[Dict]:
        """通知先の追加・編集ダイアログ。OK なら設定ファイルの notifications[] の 1 件を返す"""
        current = dict(current or {"name": "", "type": "teams", "url": "", "enabled": True,
                                   "events": ["scan_complete", "scan_error"]})
        win = tk.Toplevel(self.root)
        win.title("通知先の編集" if index is not None else "通知先の追加")
        win.transient(self.root)
        win.resizable(False, False)
        body = ttk.Frame(win, padding=12)
        body.pack(fill=tk.BOTH, expand=True)

        v_name = tk.StringVar(value=current.get("name", ""))
        v_type = tk.StringVar(value=str(current.get("type", "teams")).lower())
        v_url = tk.StringVar(value=current.get("url") or current.get("webhook_url") or "")
        v_enabled = tk.BooleanVar(value=bool(current.get("enabled", True)))
        v_timeout = tk.StringVar(value=str(current.get("timeout", 10)))
        v_retry = tk.StringVar(value=str(current.get("retry_count", 3)))
        chosen = set(current.get("events") or [])
        v_events = {t: tk.BooleanVar(value=t.value in chosen) for t in CONFIGURABLE_EVENTS}

        rows = [("名前", ttk.Entry(body, textvariable=v_name, width=30)),
                ("通知方法", ttk.Combobox(body, textvariable=v_type, values=list(NOTIFICATION_TYPES),
                                         state="readonly", width=12)),
                ("URL", ttk.Entry(body, textvariable=v_url, width=60))]
        for r, (label, widget) in enumerate(rows):
            ttk.Label(body, text=label, width=12).grid(row=r, column=0, sticky=tk.W, pady=3)
            widget.grid(row=r, column=1, columnspan=3, sticky=tk.W, pady=3)
        ttk.Label(body, text="Teams: ワークフロー「Webhook 要求を受信したらチャネルに投稿する」の URL / "
                             "Slack: Incoming Webhook の URL / webhook: 任意の受信 URL（JSON を POST）",
                  style="Hint.TLabel", wraplength=520, justify=tk.LEFT).grid(row=3, column=1, columnspan=3, sticky=tk.W)

        ev = ttk.LabelFrame(body, text="通知する出来事（何も選ばないと、すべて通知）", padding=6)
        ev.grid(row=4, column=0, columnspan=4, sticky=tk.EW, pady=(8, 4))
        for i, (t, label) in enumerate(CONFIGURABLE_EVENTS.items()):
            ttk.Checkbutton(ev, text=label, variable=v_events[t]).grid(row=i // 2, column=i % 2, sticky=tk.W, padx=(0, 16))

        ttk.Label(body, text="タイムアウト(秒)", width=12).grid(row=5, column=0, sticky=tk.W, pady=3)
        ttk.Entry(body, textvariable=v_timeout, width=6).grid(row=5, column=1, sticky=tk.W)
        ttk.Label(body, text="送信回数").grid(row=5, column=2, sticky=tk.E, padx=(10, 4))
        ttk.Entry(body, textvariable=v_retry, width=6).grid(row=5, column=3, sticky=tk.W)
        ttk.Checkbutton(body, text="この通知先を有効にする", variable=v_enabled).grid(
            row=6, column=0, columnspan=4, sticky=tk.W, pady=(6, 0))

        result: Dict = {}

        def on_ok() -> None:
            name = v_name.get().strip()
            url = v_url.get().strip()
            try:
                if not name:
                    raise ValueError("名前を入力してください。")
                if any(d.get("name") == name for i, d in enumerate(self.notify_destinations) if i != index):
                    raise ValueError(f"名前「{name}」はすでに使われています。")
                if not url.lower().startswith(("http://", "https://")):
                    raise ValueError("URL は http:// または https:// で始めてください。")
                timeout = float(v_timeout.get())
                retry = int(v_retry.get())
                if timeout <= 0 or retry < 1:
                    raise ValueError
            except ValueError as e:
                messagebox.showwarning("入力エラー", str(e) or "タイムアウトは正の数、送信回数は 1 以上の整数にしてください。",
                                       parent=win)
                return
            result.update(current)   # keep keys this dialog does not edit (e.g. format, headers)
            result.update({
                "name": name, "type": v_type.get(), "url": url, "enabled": v_enabled.get(),
                "events": [t.value for t, var in v_events.items() if var.get()],
                "timeout": timeout, "retry_count": retry,
            })
            win.destroy()

        act = ttk.Frame(body)
        act.grid(row=7, column=0, columnspan=4, sticky=tk.E, pady=(10, 0))
        ttk.Button(act, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(act, text="キャンセル", command=win.destroy).pack(side=tk.RIGHT, padx=6)
        win.grab_set()
        win.wait_window()
        return result or None

    def _test_destination(self) -> None:
        index = self._selected_destination()
        if index is None:
            return
        dest = dict(self.notify_destinations[index], enabled=True, events=[])   # すべての出来事を受ける
        manager = NotificationManager.from_config({"notifications": [dest]})
        event = NotificationEvent(
            type=NotificationType.CUSTOM, title="PLC Discovery テスト通知",
            message="PLC Discovery からのテスト通知です。この通知が届いていれば設定は正しく動作しています。",
            priority=NotificationPriority.LOW,
        )

        async def job() -> None:
            results = await manager.notify(event)
            ok = all(results.values()) and bool(results)
            name = dest.get("name", "")
            if ok:
                logging.info(f"通知先「{name}」へのテスト送信に成功しました")
            else:
                logging.error(f"通知先「{name}」へのテスト送信に失敗しました（URL・ネットワークを確認してください）")
            self._post("status", "テスト送信: " + ("成功" if ok else "失敗（ログを確認してください）"))

        self._run_job(job(), f"通知先「{dest.get('name', '')}」にテスト送信しています...")

    def _build_db_tab(self) -> None:
        f = self.tab_db
        ttk.Label(f, text="収集したデータをデータベース（SQLite）にも保存します", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(f, text="CSV に加えて、値の変化の履歴を残せます。古いデータは下の条件で自動的に整理されます。",
                  style="Hint.TLabel").pack(anchor=tk.W, pady=(0, 8))

        box = ttk.LabelFrame(f, text="データベース", padding=10)
        box.pack(fill=tk.X)
        ttk.Checkbutton(box, text="データベースに保存する", variable=self.var_db_enabled).grid(
            row=0, column=0, columnspan=3, sticky=tk.W)
        ttk.Label(box, text="ファイル", width=18).grid(row=1, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Entry(box, textvariable=self.var_db_path, width=60).grid(row=1, column=1, sticky=tk.W, pady=(6, 0))
        ttk.Button(box, text="参照...", command=self._browse_db_file).grid(row=1, column=2, padx=6, pady=(6, 0))
        ttk.Checkbutton(box, text="値の変化の履歴を記録する", variable=self.var_db_history).grid(
            row=2, column=1, sticky=tk.W, pady=(6, 0))

        clean = ttk.LabelFrame(f, text="自動整理（古いデータの削除）", padding=10)
        clean.pack(fill=tk.X, pady=10)
        rows = [
            ("保存する期間", self.var_db_days, "日", "これより古いデータを削除（0 = 期間で削除しない）"),
            ("サイズの上限", self.var_db_size, "MB", "超えたら古いデータから削除（0 = 上限なし）。各アドレスの最新値は残す"),
            ("整理の間隔", self.var_db_interval, "時間", "周期実行中に上の条件で整理する間隔（開いたときにも整理）"),
        ]
        for i, (label, var, unit, hint) in enumerate(rows):
            ttk.Label(clean, text=label, width=18).grid(row=i, column=0, sticky=tk.W, pady=3)
            ttk.Entry(clean, textvariable=var, width=8).grid(row=i, column=1, sticky=tk.W)
            ttk.Label(clean, text=unit).grid(row=i, column=2, sticky=tk.W, padx=4)
            ttk.Label(clean, text=hint, style="Hint.TLabel").grid(row=i, column=3, sticky=tk.W, padx=10)
        act = ttk.Frame(clean)
        act.grid(row=len(rows), column=0, columnspan=4, sticky=tk.W, pady=(8, 0))
        ttk.Button(act, text="今すぐ整理", command=self._clean_db_now).pack(side=tk.LEFT)
        ttk.Label(act, textvariable=self.var_db_status).pack(side=tk.LEFT, padx=10)

    def _browse_db_file(self) -> None:
        path = filedialog.asksaveasfilename(
            initialfile=Path(self.var_db_path.get() or "plc_data.db").name,
            initialdir=str(Path(self.var_db_path.get() or ".").parent),
            defaultextension=".db", filetypes=[("SQLite データベース", "*.db"), ("すべて", "*.*")])
        if path:
            self.var_db_path.set(path)

    def _clean_db_now(self) -> None:
        try:
            db_config = self._database_config(force_enabled=True)
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return

        async def job() -> None:
            def work() -> str:
                db = DatabaseExporter(db_config)   # 開くときに期間・サイズの条件で整理する
                try:
                    return f"整理しました（データ量 {db.used_bytes() / 1048576:.1f} MB）"
                finally:
                    db.close()
            message = await asyncio.get_running_loop().run_in_executor(None, work)
            logging.info(f"データベース {db_config.path}: {message}")
            self._post("db_status", message)

        self._run_job(job(), "データベースを整理しています...")

    def _float_field(self, var: tk.StringVar, label: str, minimum: float = 0.0, exclusive: bool = False) -> float:
        try:
            v = float(var.get().strip())
        except ValueError:
            raise ValueError(f"「{label}」には数値を入力してください。")
        if not math.isfinite(v):
            raise ValueError(f"「{label}」には数値を入力してください。")
        if v < minimum or (exclusive and v == minimum):
            raise ValueError(f"「{label}」は {minimum:g} {'より大きく' if exclusive else '以上に'}してください。")
        return v

    def _database_config(self, force_enabled: bool = False) -> DatabaseConfig:
        return DatabaseConfig(
            enabled=force_enabled or self.var_db_enabled.get(),
            path=self.var_db_path.get().strip() or "plc_data.db",
            track_history=self.var_db_history.get(),
            max_history_days=self._int_field(self.var_db_days, "保存する期間"),
            max_size_mb=self._float_field(self.var_db_size, "サイズの上限"),
            cleanup_interval_hours=self._float_field(self.var_db_interval, "整理の間隔", exclusive=True),
        )

    def _notification_settings(self) -> Dict:
        return {
            "report_interval_minutes": self._float_field(self.var_report_interval, "定期報告の間隔"),
            "min_interval_minutes": self._float_field(self.var_min_interval, "同じ通知の最小間隔"),
        }

    def _settings_dict(self) -> Dict:
        """③〜⑤タブの内容（設定ファイルの該当セクション）。不正な値は ValueError"""
        network = self._network_config()
        db = self._database_config()
        return {
            "network": {
                "packet_interval_ms": network.packet_interval_ms,
                "retry_interval_ms": network.retry_interval_ms,
                "request_timeout_ms": network.request_timeout_ms,
            },
            "output": {
                "directory": self.var_output_dir.get().strip() or DEFAULT_OUTPUT_DIR,
                "encoding": self.var_encoding.get(),
                "hex_addresses": self.var_hex_addresses.get(),
                "periodic_csv": self.var_periodic_csv.get(),
                "database": {
                    "enabled": db.enabled, "path": db.path, "track_history": db.track_history,
                    "max_history_days": db.max_history_days, "max_size_mb": db.max_size_mb,
                    "cleanup_interval_hours": db.cleanup_interval_hours,
                },
            },
            "notifications": [dict(d) for d in self.notify_destinations],
            "notification_settings": self._notification_settings(),
        }

    def _apply_settings(self, config: Dict) -> None:
        """読み込んだ設定（既定値と合成済み）を③〜⑤タブに反映する"""
        get = settings_file.section
        net = get(config, "network", default={}) or {}
        for var, key in ((self.var_packet_interval, "packet_interval_ms"),
                         (self.var_retry_interval, "retry_interval_ms"),
                         (self.var_timeout, "request_timeout_ms")):
            if key in net:
                var.set(str(net[key]))
        out = get(config, "output", default={}) or {}
        if out.get("directory"):
            self.var_output_dir.set(str(Path(out["directory"]).expanduser()))
        self.var_hex_addresses.set(bool(out.get("hex_addresses", False)))
        if out.get("periodic_csv") in ("per_cycle", "daily"):
            self.var_periodic_csv.set(out["periodic_csv"])
        if out.get("encoding") in ("utf-8-sig", "utf-8", "shift-jis"):
            self.var_encoding.set(out["encoding"])
        db = out.get("database") or {}
        defaults = DatabaseConfig()
        self.var_db_enabled.set(bool(db.get("enabled", False)))
        self.var_db_path.set(str(db.get("path", defaults.path)))
        self.var_db_history.set(bool(db.get("track_history", True)))
        self.var_db_days.set(str(db.get("max_history_days", defaults.max_history_days)))
        self.var_db_size.set(f"{db.get('max_size_mb', defaults.max_size_mb):g}")
        self.var_db_interval.set(f"{db.get('cleanup_interval_hours', defaults.cleanup_interval_hours):g}")
        timing = get(config, "notification_settings", default={}) or {}
        self.var_report_interval.set(f"{timing.get('report_interval_minutes', 0):g}")
        self.var_min_interval.set(f"{timing.get('min_interval_minutes', 0):g}")
        self.notify_destinations = [dict(d) for d in (get(config, "notifications", default=[]) or [])
                                    if isinstance(d, dict)]
        self._refresh_notify_tree()

    def _browse_settings_file(self) -> None:
        path = filedialog.asksaveasfilename(
            initialfile=Path(self.var_settings_path.get() or settings_file.DEFAULT_SETTINGS_FILE).name,
            initialdir=str(Path(self.var_settings_path.get() or ".").parent),
            defaultextension=".yaml", filetypes=[("YAML", "*.yaml *.yml"), ("JSON", "*.json"), ("すべて", "*.*")])
        if path:
            self.var_settings_path.set(path)

    def _save_settings(self) -> None:
        path = self.var_settings_path.get().strip()
        try:
            updates = self._settings_dict()
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return
        try:
            _, errors = settings_file.save(path, updates)
        except Exception as e:
            messagebox.showerror("保存エラー", f"設定ファイルを保存できませんでした:\n{e}")
            return
        if errors:
            messagebox.showwarning("設定の誤り", "保存しませんでした:\n" + "\n".join(errors[:10]))
            return
        logging.info(f"設定を保存しました: {path}")
        self.var_status.set(f"設定を保存しました → {path}")

    def _load_settings(self, quiet: bool = False) -> None:
        path = self.var_settings_path.get().strip()
        if not Path(path).is_file():
            if not quiet:
                messagebox.showinfo("設定の読み込み", f"設定ファイルがありません:\n{path}")
            return
        try:
            config, errors = settings_file.load(path)
        except Exception as e:
            messagebox.showerror("読み込みエラー", f"設定ファイルを読み込めませんでした:\n{e}")
            return
        self._apply_settings(config)
        if errors:
            logging.warning("設定ファイルに誤りがあります: " + " / ".join(errors[:5]))
        logging.info(f"設定を読み込みました: {path}")
        if not quiet:
            self.var_status.set(f"設定を読み込みました ← {path}")

    def _job_outputs(self) -> JobOutputs:
        """ジョブ開始時の④⑤タブの設定。不正な値は ValueError"""
        settings = self._settings_dict()
        notifier = NotificationManager.from_config(settings) if settings["notifications"] else None
        return JobOutputs(notifier, self._database_config())
