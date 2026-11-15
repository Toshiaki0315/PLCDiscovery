"""
CSV Output Module - Data Export and Reporting

Provides CSV file generation for:
- Discovery results (detected PLC list)
- PLC device data (address, value, status)
- Access denied log (inaccessible addresses)
"""

import csv
import os
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Set
import logging

from .config import PLCInfo, DataPoint, StatusCode
from .utils import get_file_timestamp, get_timestamp

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


class CSVExporter:
    """
    CSV Exporter for PLC scan results.
    
    Handles all file output operations with proper encoding
    and error handling.
    """
    
    def __init__(
        self,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        encoding: str = "utf-8"
    ):
        self.output_dir = Path(output_dir)
        self.encoding = encoding
        self._ensure_output_dir()
    
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
        
        filepath = self.output_dir / filename
        
        try:
            with open(filepath, 'w', newline='', encoding=self.encoding) as f:
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
        include_type_info: bool = True
    ) -> str:
        """
        Export PLC device data to CSV.
        
        Args:
            data_points: List of collected data points
            plc_ip: IP address of the PLC
            filename: Optional custom filename
            include_type_info: Include data type conversion columns
        
        Returns:
            Path to the created file
        """
        if not filename:
            timestamp = get_file_timestamp()
            # Sanitize IP for filename
            safe_ip = plc_ip.replace(".", "_")
            filename = f"plc_data_{safe_ip}_{timestamp}.csv"
        
        filepath = self.output_dir / filename
        
        # Check if any data point has type conversion info
        has_type_info = any(
            dp.data_type is not None or dp.converted_value is not None
            for dp in data_points
        )
        
        # Use extended headers if type info is present
        use_extended = include_type_info and has_type_info
        headers = DATA_HEADERS_EXTENDED if use_extended else DATA_HEADERS
        
        try:
            with open(filepath, 'w', newline='', encoding=self.encoding) as f:
                writer = _SafeDictWriter(f, fieldnames=headers, extrasaction='ignore')
                writer.writeheader()
                
                for dp in data_points:
                    row = dp.to_dict()
                    writer.writerow(row)
            
            logger.info(f"PLC data exported to: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Failed to export PLC data: {e}")
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
            with open(filepath, mode, newline='', encoding=self.encoding) as f:
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
            with open(filepath, 'w', newline='', encoding=self.encoding) as f:
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
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if plc_ip is None or row.get("plc_ip") == plc_ip:
                    denied.add(row["address"])
    except FileNotFoundError:
        logger.debug(f"Denied addresses file not found: {filepath}")
    except Exception as e:
        logger.warning(f"Error loading denied addresses: {e}")
    
    return denied


class ReportGenerator:
    """
    Generate formatted reports from scan data.
    """
    
    def __init__(self, exporter: CSVExporter):
        self.exporter = exporter
    
    def generate_full_report(
        self,
        plc_list: List[PLCInfo],
        data_by_plc: Dict[str, List[DataPoint]],
        denied_by_plc: Dict[str, Set[str]]
    ) -> Dict[str, str]:
        """
        Generate all report files for a scan session.
        
        Args:
            plc_list: List of scanned PLCs
            data_by_plc: Dictionary mapping IP to data points
            denied_by_plc: Dictionary mapping IP to denied addresses
        
        Returns:
            Dictionary mapping report type to filepath
        """
        files = {}
        
        # Export discovery results
        files["discovery"] = self.exporter.export_discovery_results(plc_list)
        
        # Export data for each PLC
        for plc in plc_list:
            ip = plc.ip_address
            if ip in data_by_plc:
                data_file = self.exporter.export_plc_data(data_by_plc[ip], ip)
                files[f"data_{ip}"] = data_file
            
            if ip in denied_by_plc and denied_by_plc[ip]:
                self.exporter.export_denied_addresses(denied_by_plc[ip], ip)
        
        # Generate statistics
        collection_stats = {}
        for plc in plc_list:
            ip = plc.ip_address
            data = data_by_plc.get(ip, [])
            denied = denied_by_plc.get(ip, set())
            
            total = len(data)
            success = sum(1 for dp in data if dp.status == StatusCode.OK)
            error = total - success
            
            collection_stats[ip] = {
                "total_points": total,
                "success_count": success,
                "error_count": error,
                "success_rate": f"{(success / total * 100):.2f}%" if total > 0 else "N/A",
                "denied_addresses": len(denied),
            }
        
        # Export summary
        files["summary"] = self.exporter.export_summary_report(plc_list, collection_stats)
        
        return files
    
    def print_summary(
        self,
        plc_list: List[PLCInfo],
        data_by_plc: Dict[str, List[DataPoint]],
        denied_by_plc: Dict[str, Set[str]]
    ):
        """
        Print summary to console.
        """
        print("\n" + "=" * 60)
        print("PLC Scan Summary")
        print("=" * 60)
        
        print(f"\nDiscovered PLCs: {len(plc_list)}")
        
        for plc in plc_list:
            ip = plc.ip_address
            data = data_by_plc.get(ip, [])
            denied = denied_by_plc.get(ip, set())
            
            total = len(data)
            success = sum(1 for dp in data if dp.status == StatusCode.OK)
            
            print(f"\n  {ip}")
            print(f"    Manufacturer: {plc.manufacturer or 'Unknown'}")
            print(f"    Model: {plc.model or 'Unknown'}")
            print(f"    Protocol: {plc.protocol.name if plc.protocol else 'Unknown'}")
            print(f"    Data Points: {total}")
            print(f"    Success Rate: {(success / total * 100):.2f}%" if total > 0 else "    Success Rate: N/A")
            print(f"    Denied Addresses: {len(denied)}")
        
        print("\n" + "=" * 60)

