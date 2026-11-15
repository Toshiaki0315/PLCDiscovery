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

# Manufacturer OUI prefixes (MAC address first 3 bytes)
MANUFACTURER_OUI: Dict[str, str] = {
    "00:00:1C": "三菱電機",
    "00:0D:7C": "キーエンス",
    "00:0A:DC": "オムロン",
    "00:1B:1B": "シーメンス",
    "00:A0:12": "横河電機",
    "00:10:FA": "富士電機",
    "00:0E:8C": "ロックウェル",
    "00:1D:9C": "ロックウェル",
    "00:20:4A": "パナソニック",
    "00:30:11": "東芝",
    "00:40:9D": "日立産機",
    "00:60:52": "安川電機",
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
        DeviceRange(DeviceType.DM, 0, 32767),
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

