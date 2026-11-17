"""
Configuration and Constants for PLC Discovery Tool

このモジュールは、PLCDiscoveryツール全体で使用される
設定値、定数、およびデータ構造を定義します。

主なコンポーネント:
    - Protocol: サポートされる通信プロトコル
    - DeviceType: PLCのデバイス/レジスタタイプ
    - StatusCode: データ収集のステータスコード
    - ScanMode: スキャン操作モード
    - PLCInfo: 検出されたPLC情報
    - DataPoint: PLCから取得した単一データポイント
    - NetworkConfig: ネットワークスキャン設定
    - DeviceRange: デバイスアドレス範囲

Example:
    >>> from plc_discovery.config import Protocol, PLCInfo
    >>> plc = PLCInfo(
    ...     ip_address="192.168.1.10",
    ...     protocol=Protocol.SLMP,
    ...     port=5001
    ... )
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Union


class Protocol(Enum):
    """
    サポートされるPLC通信プロトコル
    
    Attributes:
        SLMP: 三菱電機 SLMP/MCプロトコル (3Eフレーム)
        ETHERNET_IP: EtherNet/IP (CIP)
        MODBUS_TCP: Modbus/TCP
        S7: Siemens S7通信
        FINS: Omron FINS/UDP
        FINS_TCP: Omron FINS/TCP
    
    Example:
        >>> protocol = Protocol.SLMP
        >>> port = PROTOCOL_PORTS[protocol]
    """
    SLMP = auto()
    ETHERNET_IP = auto()
    MODBUS_TCP = auto()
    S7 = auto()
    FINS = auto()        # FINS over UDP
    FINS_TCP = auto()    # FINS over TCP (same port, node address handshake)


class DeviceType(Enum):
    """
    PLCデバイス/レジスタタイプ
    
    ワードデバイス:
        D: データレジスタ
        W: リンクレジスタ
        R: ファイルレジスタ
        DM: データメモリ (Omron)
        HR: 保持レジスタ (Modbus)
        IR: 入力レジスタ (Modbus)
        DB: データブロック (Siemens)
    
    ビットデバイス:
        M: 内部リレー
        X: 入力
        Y: 出力
        B: リンクリレー
        SM: 特殊リレー
    """
    # Word devices
    D = "D"
    W = "W"
    R = "R"
    DM = "DM"
    HR = "HR"
    IR = "IR"
    DB = "DB"
    
    # Bit devices
    M = "M"
    X = "X"
    Y = "Y"
    B = "B"
    SM = "SM"


class StatusCode(Enum):
    """
    データ収集ステータスコード
    
    Attributes:
        OK: 正常に読み取り完了
        NG_ILLEGAL_ADDR: アドレスが無効または未定義
        NG_TIMEOUT: リトライ後もタイムアウト
        NG_COMM_ERROR: 通信エラー
        NG_UNSUPPORTED: デバイスタイプがサポートされていない
    """
    OK = "OK"
    NG_ILLEGAL_ADDR = "NG_ILLEGAL_ADDR"
    NG_TIMEOUT = "NG_TIMEOUT"
    NG_COMM_ERROR = "NG_COMM_ERROR"
    NG_UNSUPPORTED = "NG_UNSUPPORTED"


class ScanMode(Enum):
    """
    スキャン操作モード
    
    Attributes:
        DISCOVER: 探索のみ（PLCの検出）
        FULL: フルスキャンモード（工場停止時）
        RANGE: 範囲指定モード（生産時）
    """
    DISCOVER = "discover"
    FULL = "full"
    RANGE = "range"


# Protocol-specific port numbers
PROTOCOL_PORTS: Dict[Protocol, int] = {
    Protocol.SLMP: 5001,
    Protocol.ETHERNET_IP: 44818,
    Protocol.MODBUS_TCP: 502,
    Protocol.S7: 102,
    Protocol.FINS: 9600,
    Protocol.FINS_TCP: 9600,
}

# Largest number of addresses in one user-specified range. Every address
# becomes a row in memory and in the CSV, so a typo such as 0-16000000
# would exhaust memory instead of scanning. (Full scans use fixed ranges.)
MAX_RANGE_POINTS = 1_048_576


def range_size_error(start: int, end: int) -> Optional[str]:
    """Why an address range is too large (None when it is within the limit)"""
    points = end - start + 1
    if points > MAX_RANGE_POINTS:
        return (
            f"{points:,} addresses requested; at most {MAX_RANGE_POINTS:,} "
            f"can be read in one range. Split it into smaller ranges."
        )
    return None


# Maximum words per read request (protocol limits)
MAX_READ_WORDS: Dict[Protocol, int] = {
    Protocol.SLMP: 960,
    Protocol.ETHERNET_IP: 252,
    Protocol.MODBUS_TCP: 125,
    Protocol.S7: 200,
    Protocol.FINS: 500,
    Protocol.FINS_TCP: 500,
}

# Recommended safe values for read requests
SAFE_READ_WORDS: Dict[Protocol, int] = {
    Protocol.SLMP: 900,
    Protocol.ETHERNET_IP: 200,
    Protocol.MODBUS_TCP: 100,
    Protocol.S7: 150,
    Protocol.FINS: 400,
    Protocol.FINS_TCP: 400,
}

# Manufacturer OUI prefixes (MAC address first 3 bytes).
# Every entry is the IEEE registration of that company, checked against the
# Wireshark "manuf" database.  Only blocks registered to the automation
# makers themselves are listed: PLCs built on third-party network modules
# carry the module maker's OUI and are identified by protocol instead.
MANUFACTURER_OUI: Dict[str, str] = {
    # オムロン
    "00:00:0A": "オムロン", "3C:F7:D1": "オムロン",
    # キーエンス
    "00:01:FC": "キーエンス", "74:95:A7": "キーエンス",
    # 三菱電機
    "00:26:92": "三菱電機",
    # 横河電機
    "00:00:64": "横河電機", "00:60:41": "横河電機", "D0:0A:AB": "横河電機",
    # ロックウェル (Allen-Bradley)
    "00:00:BC": "ロックウェル", "00:1D:9C": "ロックウェル", "08:61:95": "ロックウェル",
    "18:4C:08": "ロックウェル", "34:C0:F9": "ロックウェル", "40:41:01": "ロックウェル",
    "5C:21:67": "ロックウェル", "5C:88:16": "ロックウェル",
    # シーメンス
    "00:1B:1B": "シーメンス", "00:0E:8C": "シーメンス", "00:01:E3": "シーメンス",
    "00:0B:A3": "シーメンス",
    # 富士電機
    "00:40:1A": "富士電機",
    # 安川電機
    "00:20:B5": "安川電機",
    # 日立産機システム
    "A4:97:BB": "日立産機",
    # ジェイテクト
    "00:D0:7C": "ジェイテクト",
    # IDEC
    "00:03:7B": "IDEC",
    # デルタ電子
    "00:06:6E": "デルタ電子", "00:18:23": "デルタ電子", "20:F8:5E": "デルタ電子",
    # シュナイダーエレクトリック
    "00:00:54": "シュナイダー", "00:01:23": "シュナイダー",
    # 東芝
    "00:00:39": "東芝",
    # パナソニック (産業デバイス)
    "34:32:E6": "パナソニック",
}


@dataclass
class NetworkConfig:
    """
    ネットワークスキャン設定
    
    ネットワーク通信のタイミングと制限を設定します。
    PLCへの負荷を制御するため、適切な値を設定してください。
    
    Attributes:
        discovery_timeout_ms: 探索タイムアウト（ミリ秒）
        discovery_retry_count: 探索リトライ回数
        packet_interval_ms: パケット送信間隔（ミリ秒）
        retry_interval_ms: リトライ待機時間（ミリ秒）
        request_timeout_ms: リクエストタイムアウト（ミリ秒）
        max_concurrent: 最大同時接続数
    
    Example:
        >>> config = NetworkConfig(
        ...     packet_interval_ms=100,  # 100ms間隔
        ...     max_concurrent=3          # 同時3接続
        ... )
    """
    discovery_timeout_ms: int = 1000
    discovery_retry_count: int = 3
    packet_interval_ms: int = 50
    retry_interval_ms: int = 200
    request_timeout_ms: int = 5000
    max_concurrent: int = 1


@dataclass
class DeviceRange:
    """
    デバイスアドレス範囲指定
    
    スキャンするデバイスの範囲を指定します。
    
    Attributes:
        device_type: デバイスタイプ（D, M, W など）
        start_address: 開始アドレス
        end_address: 終了アドレス
    
    Properties:
        count: 範囲内のアドレス数
    
    Example:
        >>> device_range = DeviceRange(DeviceType.D, 0, 999)
        >>> print(device_range.count)  # 1000
    """
    device_type: DeviceType
    start_address: int
    end_address: int
    
    @property
    def count(self) -> int:
        """範囲内のアドレス数を返す"""
        return self.end_address - self.start_address + 1


@dataclass
class TagRange:
    """
    Symbolic tags to read (EtherNet/IP Logix controllers), used in range
    mode next to (or instead of) DeviceRange entries. Array elements are
    read with "Tag[0]{10}" (10 elements from index 0).
    """
    tags: List[str]
    
    @property
    def label(self) -> str:
        shown = ", ".join(self.tags[:3]) + (f", ... ({len(self.tags)} tags)" if len(self.tags) > 3 else "")
        return f"tags: {shown}"


# C0/C1 control characters (ESC, BEL, CSI, ...). Text reported by devices
# (EtherNet/IP product names, Modbus identification, S7 module names) is
# untrusted: escape sequences in it would drive the operator's terminal.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean_device_text(value: Any) -> Any:
    """Remove control characters from device-reported text (None/non-str unchanged)"""
    if not isinstance(value, str):
        return value
    return _CONTROL_CHARS.sub("", value).strip()


# PLCInfo fields that can hold text reported by the device
_DEVICE_TEXT_FIELDS = frozenset({"mac_address", "manufacturer", "model", "cpu_type", "firmware_version"})


@dataclass
class PLCInfo:
    """
    検出されたPLC情報
    
    PLCの識別情報と接続情報を保持します。
    
    Attributes:
        ip_address: IPアドレス
        mac_address: MACアドレス（オプション）
        manufacturer: メーカー名（オプション）
        model: 機種名（オプション）
        protocol: 通信プロトコル（オプション）
        port: ポート番号（オプション）
        cpu_type: CPUタイプ（オプション）
        firmware_version: ファームウェアバージョン（オプション）
    
    Example:
        >>> plc = PLCInfo(
        ...     ip_address="192.168.1.10",
        ...     manufacturer="Mitsubishi",
        ...     protocol=Protocol.SLMP
        ... )
    """
    ip_address: str
    mac_address: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    protocol: Optional[Protocol] = None
    port: Optional[int] = None
    cpu_type: Optional[str] = None
    firmware_version: Optional[str] = None
    # Protocol-specific handler options (e.g. FINS node numbers, S7 rack/slot);
    # passed to the protocol handler, not exported
    options: Dict[str, Any] = field(default_factory=dict)
    
    def __setattr__(self, name: str, value: Any) -> None:
        # Device-reported text never carries control characters, however
        # it is set (constructor, discovery, merge, database)
        if name in _DEVICE_TEXT_FIELDS:
            value = clean_device_text(value)
        super().__setattr__(name, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        辞書形式に変換
        
        Returns:
            PLC情報の辞書表現
        """
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address or "",
            "manufacturer": self.manufacturer or "",
            "model": self.model or "",
            "protocol": self.protocol.name if self.protocol else "",
            "port": self.port or "",
            "cpu_type": self.cpu_type or "",
            "firmware_version": self.firmware_version or "",
        }


@dataclass
class DataPoint:
    """
    PLCから取得した単一データポイント
    
    1つのアドレスから読み取った値とそのメタデータを保持します。
    データ型変換が適用された場合、converted_valueとdisplay_valueに
    変換結果が格納されます。
    
    Attributes:
        address: アドレス文字列（例: "D100", "HR0"）
        value: 生の整数値（16ビットワード）
        raw_hex: 16進数表記
        status: 読み取りステータス
        timestamp: 読み取り時刻
        data_type: データ型名（例: "FLOAT", "DWORD"）
        converted_value: 型変換後の値
        display_value: 人間が読みやすい表示形式
        raw_words: マルチワード型の生ワード値リスト
    
    Example:
        >>> dp = DataPoint(
        ...     address="D100",
        ...     value=1234,
        ...     raw_hex="04D2",
        ...     status=StatusCode.OK
        ... )
    """
    address: str
    value: Optional[int] = None
    raw_hex: Optional[str] = None
    status: StatusCode = StatusCode.OK
    timestamp: str = ""
    data_type: Optional[str] = None
    converted_value: Optional[Any] = None
    display_value: Optional[str] = None
    raw_words: Optional[List[int]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        辞書形式に変換
        
        Returns:
            データポイントの辞書表現（拡張フィールド含む）
        """
        result: Dict[str, Any] = {
            "address": self.address,
            "value": self.value if self.value is not None else "",
            "raw_hex": self.raw_hex or "",
            "status": self.status.value,
            "timestamp": self.timestamp,
        }
        if self.data_type:
            result["data_type"] = self.data_type
        if self.converted_value is not None:
            result["converted_value"] = self.converted_value
        if self.display_value:
            result["display_value"] = self.display_value
        return result


# Default device ranges for full scan by protocol
DEFAULT_DEVICE_RANGES: Dict[Protocol, List[DeviceRange]] = {
    Protocol.SLMP: [
        DeviceRange(DeviceType.D, 0, 8191),
        DeviceRange(DeviceType.M, 0, 8191),
        DeviceRange(DeviceType.W, 0, 2047),
        DeviceRange(DeviceType.R, 0, 32767),
    ],
    Protocol.ETHERNET_IP: [
        # Data files N7 / B3 of PLC-5/SLC/MicroLogix (elements 0-255).
        # Logix and generic CIP devices have no numeric addresses and report
        # these ranges as NG_UNSUPPORTED.
        DeviceRange(DeviceType.D, 0, 255),
        DeviceRange(DeviceType.M, 0, 255),
    ],
    Protocol.MODBUS_TCP: [
        DeviceRange(DeviceType.HR, 0, 9999),
        DeviceRange(DeviceType.IR, 0, 9999),
    ],
    Protocol.S7: [
        # Word indexes in DB1 (a DB holds at most 64 KB = 32768 words)
        DeviceRange(DeviceType.DB, 0, 32767),
    ],
    Protocol.FINS: [
        DeviceRange(DeviceType.DM, 0, 999),
        DeviceRange(DeviceType.HR, 0, 499),
        DeviceRange(DeviceType.W, 0, 199),
    ],
}
# FINS/TCP reads the same memory areas as FINS/UDP
DEFAULT_DEVICE_RANGES[Protocol.FINS_TCP] = DEFAULT_DEVICE_RANGES[Protocol.FINS]

