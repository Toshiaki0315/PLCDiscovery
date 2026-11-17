"""
Tag picker of the PLC Discovery GUI: reads the tag list of a Logix
controller (read-only, through EtherNetIPHandler) and lets the user pick
the tags for the "タグ（EtherNet/IP）" field of the ② データ収集 tab.
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional, Tuple

from plc_discovery.config import NetworkConfig, PROTOCOL_PORTS, Protocol
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler

# Message when the device has no tag list (Omron NJ/NX, generic CIP devices)
NO_TAG_LIST_MESSAGE = (
    "この機器はタグ一覧を返しません（オムロン NJ/NX など）。\n"
    "Sysmac Studio で「ネットワーク公開」にした変数名を、タグ欄に直接入力してください。"
)


async def fetch_tag_list(ip: str, port: Optional[int], config: NetworkConfig) -> Tuple[Optional[List[str]], str]:
    """
    Tag names of a Logix controller for a full read: controller and
    program scope, structures, arrays as "Name[0]{n}". Returns (tags, "")
    or (None, reason) when the device cannot be reached or has no tag list.
    """
    handler = EtherNetIPHandler(ip, port or PROTOCOL_PORTS[Protocol.ETHERNET_IP], config=config)
    try:
        if not await handler.connect():
            return None, f"{ip}:{handler.port} に EtherNet/IP で接続できませんでした。"
        tags = handler.tag_scan_list()
        if not tags:
            return None, NO_TAG_LIST_MESSAGE
        return tags, ""
    finally:
        await handler.disconnect()


def filter_tags(tags: List[str], text: str) -> List[str]:
    """Tags whose name contains every space-separated word of text (case-insensitive)"""
    words = text.lower().split()
    return [t for t in tags if all(w in t.lower() for w in words)]


class TagPickerDialog:
    """Modal list of tags with a filter; on OK calls on_select(selected tags)"""

    def __init__(self, parent: tk.Misc, tags: List[str], selected: List[str],
                 on_select: Callable[[List[str]], None]):
        self.tags = tags
        self.selected = [t for t in selected if t in tags]
        self.on_select = on_select
        self.top = tk.Toplevel(parent)
        self.top.title("タグの選択")
        self.top.transient(parent)
        self.top.geometry("460x520")

        frame = ttk.Frame(self.top, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text=f"コントローラのタグ {len(tags)} 件。Ctrl / Shift + クリックで複数選択できます。"
                  ).pack(anchor=tk.W)
        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=(6, 4))
        ttk.Label(row, text="絞り込み").pack(side=tk.LEFT)
        self.var_filter = tk.StringVar()
        self.var_filter.trace_add("write", lambda *_: self._refresh())
        ttk.Entry(row, textvariable=self.var_filter).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))

        body = ttk.Frame(frame)
        body.pack(fill=tk.BOTH, expand=True)
        self.listbox = tk.Listbox(body, selectmode=tk.EXTENDED, exportselection=False)
        scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scroll.set)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.bind("<<ListboxSelect>>", lambda e: self._remember())

        buttons = ttk.Frame(frame)
        buttons.pack(fill=tk.X, pady=(8, 0))
        self.lbl_count = ttk.Label(buttons, text="")
        self.lbl_count.pack(side=tk.LEFT)
        ttk.Button(buttons, text="キャンセル", command=self.top.destroy).pack(side=tk.RIGHT)
        ttk.Button(buttons, text="OK", command=self._ok).pack(side=tk.RIGHT, padx=6)
        ttk.Button(buttons, text="表示中をすべて選択", command=self._select_shown).pack(side=tk.RIGHT)

        self.shown: List[str] = []
        self._refresh()
        self.top.grab_set()

    def _refresh(self) -> None:
        self.shown = filter_tags(self.tags, self.var_filter.get())
        self.listbox.delete(0, tk.END)
        for i, tag in enumerate(self.shown):
            self.listbox.insert(tk.END, tag)
            if tag in self.selected:
                self.listbox.selection_set(i)
        self._update_count()

    def _remember(self) -> None:
        """Keep selections of tags hidden by the filter; update the shown ones"""
        chosen = {self.shown[i] for i in self.listbox.curselection()}
        shown = set(self.shown)
        self.selected = [t for t in self.tags if (t in chosen) or (t in self.selected and t not in shown)]
        self._update_count()

    def _select_shown(self) -> None:
        self.listbox.selection_set(0, tk.END)
        self._remember()

    def _update_count(self) -> None:
        self.lbl_count.configure(text=f"{len(self.selected)} 件を選択")

    def _ok(self) -> None:
        self.on_select(list(self.selected))
        self.top.destroy()
