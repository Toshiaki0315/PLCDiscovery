"""
CSV Output Module - Data Export and Reporting

Provides CSV file generation for:
- Discovery results (detected PLC list)
- PLC device data (address, value, status)
- Access denied log (inaccessible addresses)
"""

import csv
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Set
import logging

from .config import PLCInfo, DataPoint, StatusCode
from .utils import get_file_timestamp, get_timestamp, melsec_address

logger = logging.getLogger(__name__)

# Default output directory
DEFAULT_OUTPUT_DIR = "./plc_scan_results"

# CSV column headers
DISCOVERY_HEADERS = [
    "ip_address",
    "mac_address",
    "manufacturer",
    "model",
    "protocol",
    "port",
    "cpu_type",
    "firmware_version",
    "read_method",
    "discovered_at"
]

DATA_HEADERS = [
    "address",
    "value",
    "raw_hex",
    "status",
    "timestamp"
]

# Extended headers for data with type conversion
DATA_HEADERS_EXTENDED = [
    "address",
    "value",
    "raw_hex",
    "data_type",
    "converted_value",
    "display_value",
    "status",
    "timestamp"
]

DENIED_HEADERS = [
    "address",
    "status",
    "last_attempt",
    "plc_ip"
]


# Leading characters that make spreadsheet applications treat a cell as a
# formula (CSV/formula injection, OWASP). Device-reported strings such as
# Modbus/EtherNet/IP identity names end up in CSVs opened in Excel.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _is_number(text: str) -> bool:
    try:
        float(text)
        return True
    except ValueError:
        return False


def csv_safe(value):
    """
    Neutralize a value that a spreadsheet would evaluate as a formula by
    prefixing it with a single quote. Numbers (including negative numbers
    and numeric strings like "-12.5") are left unchanged.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES) and not _is_number(value):
        return "'" + value
    return value


class _SafeDictWriter(csv.DictWriter):
    """csv.DictWriter that applies csv_safe() to every cell"""

    def writerow(self, rowdict):
        return super().writerow({k: csv_safe(v) for k, v in rowdict.items()})


# Encodings accepted for CSV output. Shift-JIS variants are written as CP932
# (what Excel and Japanese Windows actually use; Python's "shift_jis" lacks
# characters such as ① ㈱ ～).
_ENCODING_ALIASES = {
    "shift-jis": "cp932", "shift_jis": "cp932", "sjis": "cp932", "cp932": "cp932",
    "ms932": "cp932", "windows-31j": "cp932",
    "utf-8-sig": "utf-8-sig", "utf8-sig": "utf-8-sig", "utf-8-bom": "utf-8-sig",
    "utf-8": "utf-8", "utf8": "utf-8",
}


def normalize_csv_encoding(encoding: str) -> str:
    """Map a user-facing encoding name to the codec used for CSV files"""
    return _ENCODING_ALIASES.get((encoding or "utf-8").lower(), encoding)


def _unique_path(path: Path) -> Path:
    """Return path, or path with _1, _2, ... appended if it already exists
    (file names have one-second resolution)"""
    if not path.exists():
        return path
    n = 1
    while True:
        candidate = path.with_name(f"{path.stem}_{n}{path.suffix}")
        if not candidate.exists():
            return candidate
        n += 1


class CSVExporter:
    """
    CSV Exporter for PLC scan results.

    Handles all file output operations with proper encoding
    and error handling.
    """

    def __init__(
        self,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        encoding: str = "utf-8",
        hex_addresses: bool = False
    ):
        self.output_dir = Path(output_dir)
        self.encoding = normalize_csv_encoding(encoding)
        # Add MELSEC hex addresses to data files of SLMP targets (callers
        # pass hex_addresses=True to export_plc_data for those)
        self.hex_addresses = hex_addresses
        # Periodic scans: "per_cycle" (one file per cycle) or "daily"
        # (append to one file per day, see append_plc_data)
        self.periodic_csv = "per_cycle"
        self._ensure_output_dir()

    def _open_csv(self, filepath: Path, mode: str = "w"):
        """
        Open a CSV file for writing.

        - CP932: characters that cannot be represented (e.g. "ü" in a device
          name) are replaced with "?" instead of failing the whole file.
        - UTF-8 with BOM (Excel-friendly): the BOM is written only when the
          file is created, never again when appending.
        """
        encoding = self.encoding
        if encoding == "utf-8-sig" and mode == "a" and filepath.exists() and filepath.stat().st_size > 0:
            encoding = "utf-8"
        errors = "replace" if encoding == "cp932" else "strict"
        return open(filepath, mode, newline="", encoding=encoding, errors=errors)

    def _ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create output directory: {e}")
            raise

    def export_discovery_results(
        self,
        plc_list: List[PLCInfo],
        filename: Optional[str] = None
    ) -> str:
        """
        Export PLC discovery results to CSV.

        Args:
            plc_list: List of discovered PLCs
            filename: Optional custom filename

        Returns:
            Path to the created file
        """
        if not filename:
            timestamp = get_file_timestamp()
            filename = f"discovery_result_{timestamp}.csv"
            filepath = _unique_path(self.output_dir / filename)
        else:
            filepath = self.output_dir / filename

        try:
            with self._open_csv(filepath, 'w') as f:
                writer = _SafeDictWriter(f, fieldnames=DISCOVERY_HEADERS)
                writer.writeheader()

                discovered_at = get_timestamp()

                for plc in plc_list:
                    row = plc.to_dict()
                    row["discovered_at"] = discovered_at
                    writer.writerow(row)

            logger.info(f"Discovery results exported to: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to export discovery results: {e}")
            raise

    def export_plc_data(
        self,
        data_points: List[DataPoint],
        plc_ip: str,
        filename: Optional[str] = None,
        include_type_info: bool = True,
        target_tag: Optional[str] = None,
        hex_addresses: bool = False
    ) -> str:
        """
        Export PLC device data to CSV.

        Args:
            data_points: List of collected data points
            plc_ip: IP address of the PLC
            filename: Optional custom filename
            include_type_info: Include data type conversion columns
            target_tag: Protocol and port (e.g. "SLMP_5001") added to the
                file name when several targets share the IP, so each file
                can be told apart
            hex_addresses: add an "address_hex" column with the address in
                MELSEC notation (X/Y/B/W in hexadecimal, e.g. X31 -> X1F)

        Returns:
            Path to the created file
        """
        if not filename:
            timestamp = get_file_timestamp()
            # Sanitize IP for filename
            safe_ip = plc_ip.replace(".", "_")
            tag = f"_{target_tag}" if target_tag else ""
            filename = f"plc_data_{safe_ip}{tag}_{timestamp}.csv"
            filepath = _unique_path(self.output_dir / filename)
        else:
            filepath = self.output_dir / filename

        # Check if any data point has type conversion info
        has_type_info = any(
            dp.data_type is not None or dp.converted_value is not None
            for dp in data_points
        )

        # Use extended headers if type info is present
        use_extended = include_type_info and has_type_info
        headers = list(DATA_HEADERS_EXTENDED if use_extended else DATA_HEADERS)
        if hex_addresses:
            headers.insert(1, "address_hex")

        try:
            with self._open_csv(filepath, 'w') as f:
                writer = _SafeDictWriter(f, fieldnames=headers, extrasaction='ignore')
                writer.writeheader()

                for dp in data_points:
                    row = dp.to_dict()
                    if hex_addresses:
                        row["address_hex"] = melsec_address(dp.address)
                    writer.writerow(row)

            logger.info(f"PLC data exported to: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to export PLC data: {e}")
            raise

    def append_plc_data(
        self,
        data_points: List[DataPoint],
        plc_ip: str,
        target_tag: Optional[str] = None,
        hex_addresses: bool = False,
    ) -> str:
        """
        Append PLC data to one file per day: plc_data_<IP>[_<tag>]_YYYYMMDD.csv

        For periodic scans (output.periodic_csv: daily): one file per cycle
        meant 1440 files a day at 60 s. Every row keeps its own timestamp,
        so cycles can be told apart; the columns are always the extended
        set, so cycles with and without conversion fit the same file.
        """
        safe_ip = plc_ip.replace(".", "_")
        tag = f"_{target_tag}" if target_tag else ""
        filepath = self.output_dir / f"plc_data_{safe_ip}{tag}_{get_file_timestamp()[:8]}.csv"
        headers = list(DATA_HEADERS_EXTENDED)
        if hex_addresses:
            headers.insert(1, "address_hex")
        new_file = not filepath.exists() or filepath.stat().st_size == 0
        if not new_file:
            # Columns of an existing file win (e.g. address_hex switched later)
            with open(filepath, encoding=self.encoding, errors="replace", newline="") as f:
                first = f.readline().lstrip("\ufeff").strip()
            if first:
                headers = next(csv.reader([first]))
        try:
            with self._open_csv(filepath, 'a') as f:
                writer = _SafeDictWriter(f, fieldnames=headers, extrasaction='ignore')
                if new_file:
                    writer.writeheader()
                for dp in data_points:
                    row = dp.to_dict()
                    if "address_hex" in headers:
                        row["address_hex"] = melsec_address(dp.address)
                    writer.writerow(row)
            logger.info(f"PLC data appended to: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Failed to append PLC data: {e}")
            raise

    def export_denied_addresses(
        self,
        denied_addresses: Set[str],
        plc_ip: str,
        status: StatusCode = StatusCode.NG_ILLEGAL_ADDR,
        filename: Optional[str] = None,
        statuses: Optional[Mapping[str, StatusCode]] = None
    ) -> str:
        """
        Export inaccessible addresses log to CSV.

        Args:
            denied_addresses: Set of address strings
            plc_ip: IP address of the PLC
            status: Status code for addresses missing from ``statuses``
            filename: Optional custom filename
            statuses: Per-address status (e.g. NG_UNSUPPORTED)

        Returns:
            Path to the created file
        """
        if not filename:
            filename = "access_denied_log.csv"

        filepath = self.output_dir / filename

        # Check if file exists for append mode
        file_exists = filepath.exists()

        try:
            mode = 'a' if file_exists else 'w'
            with self._open_csv(filepath, mode) as f:
                writer = _SafeDictWriter(f, fieldnames=DENIED_HEADERS)

                if not file_exists:
                    writer.writeheader()

                timestamp = get_timestamp()

                for address in sorted(denied_addresses):
                    address_status = (statuses or {}).get(address) or status
                    writer.writerow({
                        "address": address,
                        "status": address_status.value,
                        "last_attempt": timestamp,
                        "plc_ip": plc_ip
                    })

            logger.info(f"Denied addresses exported to: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to export denied addresses: {e}")
            raise

    def export_summary_report(
        self,
        plc_list: List[PLCInfo],
        collection_stats: Dict[str, Dict],
        filename: Optional[str] = None
    ) -> str:
        """
        Export summary report with collection statistics.

        Args:
            plc_list: List of scanned PLCs
            collection_stats: Dictionary mapping IP to statistics
            filename: Optional custom filename

        Returns:
            Path to the created file
        """
        if not filename:
            timestamp = get_file_timestamp()
            filename = f"scan_summary_{timestamp}.csv"
            filepath = _unique_path(self.output_dir / filename)
        else:
            filepath = self.output_dir / filename

        summary_headers = [
            "ip_address",
            "manufacturer",
            "model",
            "protocol",
            "total_points",
            "success_count",
            "error_count",
            "success_rate",
            "denied_addresses"
        ]

        try:
            with self._open_csv(filepath, 'w') as f:
                writer = _SafeDictWriter(f, fieldnames=summary_headers)
                writer.writeheader()

                for plc in plc_list:
                    stats = collection_stats.get(plc.ip_address, {})
                    writer.writerow({
                        "ip_address": plc.ip_address,
                        "manufacturer": plc.manufacturer or "",
                        "model": plc.model or "",
                        "protocol": plc.protocol.name if plc.protocol else "",
                        "total_points": stats.get("total_points", 0),
                        "success_count": stats.get("success_count", 0),
                        "error_count": stats.get("error_count", 0),
                        "success_rate": stats.get("success_rate", "N/A"),
                        "denied_addresses": stats.get("denied_addresses", 0),
                    })

            logger.info(f"Summary report exported to: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to export summary report: {e}")
            raise


def load_denied_addresses(
    filepath: str,
    plc_ip: Optional[str] = None
) -> Set[str]:
    """
    Load previously recorded denied addresses from CSV.

    Args:
        filepath: Path to denied addresses log file
        plc_ip: Optional filter by PLC IP

    Returns:
        Set of address strings
    """
    denied = set()

    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:   # also strips a BOM
            reader = csv.DictReader(f)
            for row in reader:
                if plc_ip is None or row.get("plc_ip") == plc_ip:
                    denied.add(row["address"])
    except FileNotFoundError:
        logger.debug(f"Denied addresses file not found: {filepath}")
    except Exception as e:
        logger.warning(f"Error loading denied addresses: {e}")

    return denied
