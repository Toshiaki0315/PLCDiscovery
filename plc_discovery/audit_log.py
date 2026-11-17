"""
Audit Log Module

Provides comprehensive audit logging for PLC communications.
All read operations are logged with timestamps, addresses, and results.
"""

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events"""

    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    DISCOVERY_START = "DISCOVERY_START"
    DISCOVERY_RESULT = "DISCOVERY_RESULT"
    CONNECT = "CONNECT"
    DISCONNECT = "DISCONNECT"
    READ_REQUEST = "READ_REQUEST"
    READ_SUCCESS = "READ_SUCCESS"
    READ_ERROR = "READ_ERROR"
    SCAN_START = "SCAN_START"
    SCAN_COMPLETE = "SCAN_COMPLETE"
    ERROR = "ERROR"
    WARNING = "WARNING"


@dataclass
class AuditEvent:
    """Audit log event"""

    timestamp: str
    event_type: str
    session_id: str
    plc_ip: Optional[str] = None
    protocol: Optional[str] = None
    device: Optional[str] = None
    address_start: Optional[int] = None
    address_end: Optional[int] = None
    count: Optional[int] = None
    status: Optional[str] = None
    error_message: Optional[str] = None
    duration_ms: Optional[float] = None
    data_points: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values"""
        return {k: v for k, v in asdict(self).items() if v is not None}

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), ensure_ascii=False)


class AuditLogger:
    """
    Audit logger for PLC operations.

    Logs all operations to file in JSON Lines format for easy parsing.
    Thread-safe implementation.
    """

    # The process-wide instance is managed by init_audit_logger() /
    # get_audit_logger(). The class itself is not a singleton: a singleton
    # silently ignored the log file passed to a later init_audit_logger().

    def __init__(self, log_file: Optional[str] = None, enabled: bool = True, console_output: bool = False):
        self.log_file = log_file
        self.enabled = enabled
        self.console_output = console_output
        self._session_id = self._generate_session_id()
        self._file_handle: Optional[TextIO] = None
        self._write_lock = threading.Lock()
        self._initialized = True

        if log_file and enabled:
            self._open_log_file()

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return datetime.now().strftime("%Y%m%d_%H%M%S_") + os.urandom(4).hex()

    def _open_log_file(self) -> None:
        """Open log file for writing"""
        if not self.log_file:
            return
        try:
            path = Path(self.log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(path, "a", encoding="utf-8")
            logger.info(f"Audit log opened: {self.log_file}")
        except Exception as e:
            logger.error(f"Failed to open audit log file: {e}")
            self._file_handle = None

    def _write_event(self, event: AuditEvent) -> None:
        """Write event to log file"""
        if not self.enabled:
            return

        with self._write_lock:
            line = event.to_json() + "\n"

            if self._file_handle:
                try:
                    self._file_handle.write(line)
                    self._file_handle.flush()
                except Exception as e:
                    logger.error(f"Failed to write audit log: {e}")

            if self.console_output:
                print(f"[AUDIT] {line.strip()}")

    def _create_event(self, event_type: AuditEventType, **kwargs: Any) -> AuditEvent:
        """Create audit event with common fields"""
        return AuditEvent(
            timestamp=datetime.now().isoformat(), event_type=event_type.value, session_id=self._session_id, **kwargs
        )

    def log_session_start(self, metadata: Optional[Dict] = None) -> None:
        """Log session start"""
        event = self._create_event(AuditEventType.SESSION_START, metadata=metadata)
        self._write_event(event)

    def log_session_end(self, metadata: Optional[Dict] = None) -> None:
        """Log session end"""
        event = self._create_event(AuditEventType.SESSION_END, metadata=metadata)
        self._write_event(event)

    def log_discovery_start(self, ip_ranges: List[str]) -> None:
        """Log discovery start"""
        event = self._create_event(AuditEventType.DISCOVERY_START, metadata={"ip_ranges": ip_ranges})
        self._write_event(event)

    def log_discovery_result(self, plc_count: int, plcs: List[Dict]) -> None:
        """Log discovery result"""
        event = self._create_event(
            AuditEventType.DISCOVERY_RESULT, data_points=plc_count, metadata={"discovered_plcs": plcs}
        )
        self._write_event(event)

    def log_connect(
        self, plc_ip: str, protocol: str, port: int, success: bool, error_message: Optional[str] = None
    ) -> None:
        """Log connection attempt"""
        event = self._create_event(
            AuditEventType.CONNECT,
            plc_ip=plc_ip,
            protocol=protocol,
            status="SUCCESS" if success else "FAILED",
            error_message=error_message,
            metadata={"port": port},
        )
        self._write_event(event)

    def log_disconnect(self, plc_ip: str, protocol: str) -> None:
        """Log disconnection"""
        event = self._create_event(AuditEventType.DISCONNECT, plc_ip=plc_ip, protocol=protocol)
        self._write_event(event)

    def log_read_request(self, plc_ip: str, protocol: str, device: str, address_start: int, address_end: int) -> None:
        """Log read request"""
        event = self._create_event(
            AuditEventType.READ_REQUEST,
            plc_ip=plc_ip,
            protocol=protocol,
            device=device,
            address_start=address_start,
            address_end=address_end,
            count=address_end - address_start + 1,
        )
        self._write_event(event)

    def log_read_success(
        self,
        plc_ip: str,
        protocol: str,
        device: str,
        address_start: int,
        address_end: int,
        data_points: int,
        duration_ms: float,
    ) -> None:
        """Log successful read"""
        event = self._create_event(
            AuditEventType.READ_SUCCESS,
            plc_ip=plc_ip,
            protocol=protocol,
            device=device,
            address_start=address_start,
            address_end=address_end,
            count=address_end - address_start + 1,
            data_points=data_points,
            duration_ms=duration_ms,
            status="SUCCESS",
        )
        self._write_event(event)

    def log_read_error(
        self,
        plc_ip: str,
        protocol: str,
        device: str,
        address_start: int,
        address_end: int,
        error_message: str,
        duration_ms: float,
    ) -> None:
        """Log read error"""
        event = self._create_event(
            AuditEventType.READ_ERROR,
            plc_ip=plc_ip,
            protocol=protocol,
            device=device,
            address_start=address_start,
            address_end=address_end,
            error_message=error_message,
            duration_ms=duration_ms,
            status="ERROR",
        )
        self._write_event(event)

    def log_scan_start(self, plc_ip: str, mode: str, device_ranges: Optional[List[str]] = None) -> None:
        """Log scan start"""
        event = self._create_event(
            AuditEventType.SCAN_START, plc_ip=plc_ip, metadata={"mode": mode, "device_ranges": device_ranges}
        )
        self._write_event(event)

    def log_scan_complete(
        self, plc_ip: str, total_points: int, success_count: int, error_count: int, duration_ms: float
    ) -> None:
        """Log scan completion"""
        event = self._create_event(
            AuditEventType.SCAN_COMPLETE,
            plc_ip=plc_ip,
            data_points=total_points,
            duration_ms=duration_ms,
            metadata={
                "success_count": success_count,
                "error_count": error_count,
                "success_rate": f"{(success_count / total_points * 100):.2f}%" if total_points > 0 else "N/A",
            },
        )
        self._write_event(event)

    def log_error(self, message: str, metadata: Optional[Dict] = None) -> None:
        """Log general error"""
        event = self._create_event(AuditEventType.ERROR, error_message=message, metadata=metadata)
        self._write_event(event)

    def log_warning(self, message: str, metadata: Optional[Dict] = None) -> None:
        """Log warning"""
        event = self._create_event(AuditEventType.WARNING, error_message=message, metadata=metadata)
        self._write_event(event)

    def close(self):
        """Close audit log file"""
        if self._file_handle:
            try:
                self._file_handle.close()
                logger.info("Audit log closed")
            except Exception as e:
                logger.error(f"Error closing audit log: {e}")
            finally:
                self._file_handle = None

    def get_session_id(self) -> str:
        """Get current session ID"""
        return self._session_id

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable audit logging"""
        self.enabled = enabled

    def set_log_file(self, log_file: str) -> None:
        """Set or change log file"""
        if self._file_handle:
            self.close()
        self.log_file = log_file
        if self.enabled:
            self._open_log_file()


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def init_audit_logger(
    log_file: Optional[str] = None, enabled: bool = True, console_output: bool = False
) -> AuditLogger:
    """Initialize (or re-initialize) the global audit logger"""
    global _audit_logger
    if _audit_logger is not None:
        _audit_logger.close()
    _audit_logger = AuditLogger(log_file=log_file, enabled=enabled, console_output=console_output)
    return _audit_logger


def close_audit_logger():
    """Close global audit logger"""
    global _audit_logger
    if _audit_logger:
        _audit_logger.close()
        _audit_logger = None
