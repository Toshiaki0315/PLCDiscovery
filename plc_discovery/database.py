"""
Database Output Module - SQLite Data Storage

Provides SQLite database storage for:
- Discovery results
- PLC device data with history
- Access denied logs
- Scan statistics

Features:
- Optional enable/disable
- Automatic schema creation
- Data versioning and history
- Query interface for analysis
"""

import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set

from .config import DataPoint, PLCInfo, StatusCode
from .report import json_safe

logger = logging.getLogger(__name__)


# Default for how often a long run (periodic monitoring) applies
# max_history_days / max_size_mb (output.database.cleanup_interval_hours)
CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60

# Database schema version for migrations
SCHEMA_VERSION = 3

# Tables whose rows belong to one scan target: since schema v3 they record
# the protocol and port next to the IP, so targets sharing an IP (one PLC
# read over two protocols, a gateway, simulators) are kept apart
TARGET_TABLES = ("data_points", "denied_addresses", "data_history")

# SQL statements for schema creation
CREATE_TABLES_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL
);

-- Discovered PLCs
CREATE TABLE IF NOT EXISTS plcs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    manufacturer TEXT,
    model TEXT,
    protocol TEXT,
    port INTEGER,
    cpu_type TEXT,
    firmware_version TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

-- Scan sessions
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    mode TEXT NOT NULL,
    plc_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running'
);

-- Data points (main data storage)
CREATE TABLE IF NOT EXISTS data_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    plc_ip TEXT NOT NULL,
    protocol TEXT,
    port INTEGER,
    address TEXT NOT NULL,
    value INTEGER,
    raw_hex TEXT,
    data_type TEXT,
    converted_value TEXT,
    display_value TEXT,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

-- Denied addresses log
CREATE TABLE IF NOT EXISTS denied_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    plc_ip TEXT NOT NULL,
    protocol TEXT,
    port INTEGER,
    address TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

-- Data change history (for tracking changes)
CREATE TABLE IF NOT EXISTS data_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plc_ip TEXT NOT NULL,
    protocol TEXT,
    port INTEGER,
    address TEXT NOT NULL,
    old_value INTEGER,
    new_value INTEGER,
    changed_at TEXT NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_data_points_plc_ip ON data_points(plc_ip);
CREATE INDEX IF NOT EXISTS idx_data_points_plc_addr_id ON data_points(plc_ip, address, id);
CREATE INDEX IF NOT EXISTS idx_data_points_target ON data_points(plc_ip, protocol, port, address, id);
CREATE INDEX IF NOT EXISTS idx_history_plc_ip ON data_history(plc_ip);
CREATE INDEX IF NOT EXISTS idx_history_address ON data_history(address);
CREATE INDEX IF NOT EXISTS idx_history_changed_at ON data_history(changed_at);
CREATE INDEX IF NOT EXISTS idx_data_points_address ON data_points(address);
CREATE INDEX IF NOT EXISTS idx_data_points_timestamp ON data_points(timestamp);
CREATE INDEX IF NOT EXISTS idx_data_points_session ON data_points(session_id);
CREATE INDEX IF NOT EXISTS idx_denied_plc_ip ON denied_addresses(plc_ip);
CREATE INDEX IF NOT EXISTS idx_plcs_ip ON plcs(ip_address);
-- One row per IP, protocol and port (schema v2): a PLC answering on
-- several protocols, or several simulators on one host, keeps every entry
CREATE UNIQUE INDEX IF NOT EXISTS idx_plcs_identity
    ON plcs(ip_address, IFNULL(protocol, ''), IFNULL(port, 0));
"""


@dataclass
class DatabaseConfig:
    """Configuration for database output"""

    enabled: bool = False
    path: str = "./plc_data.db"
    track_history: bool = True
    # Data older than this is deleted when the database is opened and every
    # cleanup_interval_hours during long runs (0 = keep everything)
    max_history_days: int = 30
    # Upper limit of the data in the database in MB: the oldest rows are
    # deleted until it fits (0 = no limit). The latest value per address is
    # always kept.
    max_size_mb: float = 0
    # How often a long run (periodic monitoring) applies the two limits
    cleanup_interval_hours: float = 24

    @classmethod
    def from_dict(cls, config: Dict) -> "DatabaseConfig":
        """Create from dictionary"""
        return cls(
            enabled=config.get("enabled", False),
            path=config.get("path", "./plc_data.db"),
            track_history=config.get("track_history", True),
            max_history_days=config.get("max_history_days", 30),
            max_size_mb=config.get("max_size_mb", 0) or 0,
            cleanup_interval_hours=config.get("cleanup_interval_hours", 24) or 24,
        )


def _sqlite_integer(value: Optional[int]) -> Optional[int]:
    """
    The value as SQLite can store it (a signed 64-bit INTEGER), else None.
    An unsigned 64-bit tag (ULINT / LWORD) with the top bit set does not
    fit: its row is stored without the number - raw_hex still holds it -
    instead of being dropped with an OverflowError.
    """
    if isinstance(value, int) and not -(2**63) <= value < 2**63:
        return None
    return value


class DatabaseExporter:
    """
    SQLite database exporter for PLC scan data.

    Provides persistent storage with history tracking and query capabilities.
    Can be enabled/disabled via configuration.

    Usage:
        # Create with config
        config = DatabaseConfig(enabled=True, path="./plc_data.db")
        db = DatabaseExporter(config)

        # Or create directly
        db = DatabaseExporter.create("./plc_data.db")

        # Export data
        with db.session() as session_id:
            db.export_plc_data(data_points, "192.168.1.10", session_id)

        # Query history
        history = db.get_address_history("192.168.1.10", "D100", days=7)
    """

    def __init__(self, config: Optional[DatabaseConfig] = None):
        """
        Initialize database exporter.

        Args:
            config: Database configuration (default: disabled)
        """
        self.config = config or DatabaseConfig()
        self._connection: Optional[sqlite3.Connection] = None
        self._current_session_id: Optional[int] = None
        # Latest value per address, per PLC: loaded from the database once,
        # then kept up to date in memory so periodic exports do not re-scan
        # the whole data_points table every cycle
        self._latest_values: Dict[tuple, Dict[str, int]] = {}
        self._last_cleanup: Optional[float] = None

        if self.config.enabled:
            self._initialize_database()

    @classmethod
    def create(cls, path: str, track_history: bool = True) -> "DatabaseExporter":
        """
        Create an enabled database exporter.

        Args:
            path: Database file path
            track_history: Enable change history tracking

        Returns:
            Configured DatabaseExporter instance
        """
        config = DatabaseConfig(enabled=True, path=path, track_history=track_history)
        return cls(config)

    def _rollback_quietly(self) -> None:
        """Drop the rows of an export that failed half-way (never raises)"""
        try:
            if self._connection is not None:
                self._connection.rollback()
        except Exception as e:
            logger.debug(f"Rollback failed: {e}")

    @property
    def is_enabled(self) -> bool:
        """Check if database output is enabled"""
        return self.config.enabled

    def _initialize_database(self):
        """Initialize database and create schema"""
        try:
            db_path = Path(self.config.path)
            db_path.parent.mkdir(parents=True, exist_ok=True)

            self._connection = sqlite3.connect(str(db_path), check_same_thread=False)
            self._connection.row_factory = sqlite3.Row

            # Databases created by schema v1 allowed one PLC row per IP;
            # rebuild that table before the v2 indexes are created
            self._migrate_plcs_table()
            # Schema v2 -> v3: protocol/port columns on per-target tables
            self._add_target_columns()

            # Create tables
            self._db.executescript(CREATE_TABLES_SQL)

            # Check/update schema version
            cursor = self._db.execute("SELECT version FROM schema_info ORDER BY version DESC LIMIT 1")
            row = cursor.fetchone()

            if not row or row[0] < SCHEMA_VERSION:
                self._db.execute(
                    "INSERT INTO schema_info (version, created_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, datetime.now().isoformat()),
                )

            self._db.commit()
            logger.info(f"Database initialized: {self.config.path}")

            # Apply max_history_days (it was never applied automatically, so
            # a monitoring database grew without limit: ~330 MB a day for
            # 1000 points every 60 s). Space is reclaimed only if rows went.
            self._apply_retention(vacuum=True)

        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            self.config.enabled = False
            raise

    def _migrate_plcs_table(self):
        """Schema v1 -> v2: drop UNIQUE(ip_address) from the plcs table"""
        row = self._db.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'plcs'").fetchone()
        if not row or "UNIQUE(ip_address)" not in row[0].replace(" ", ""):
            return
        logger.info("Upgrading database schema: one PLC row per IP, protocol and port")
        columns = (
            "id, ip_address, mac_address, manufacturer, model, protocol, port, "
            "cpu_type, firmware_version, first_seen, last_seen"
        )
        self._db.commit()
        with self._db:  # one transaction: all or nothing
            # Explicit BEGIN: sqlite3 opens a transaction by itself only for
            # INSERT/UPDATE/DELETE, so the RENAME and CREATE were committed
            # one by one and a failure half-way left an empty plcs table
            self._db.execute("BEGIN")
            self._db.execute("ALTER TABLE plcs RENAME TO plcs_v1")
            self._db.execute("""
                CREATE TABLE plcs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    manufacturer TEXT,
                    model TEXT,
                    protocol TEXT,
                    port INTEGER,
                    cpu_type TEXT,
                    firmware_version TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
            """)
            self._db.execute(f"INSERT INTO plcs ({columns}) SELECT {columns} FROM plcs_v1")
            self._db.execute("DROP TABLE plcs_v1")

    def _add_target_columns(self):
        """Schema v2 -> v3: add protocol and port to the per-target tables"""
        for table in TARGET_TABLES:
            columns = {row[1] for row in self._db.execute(f"PRAGMA table_info({table})")}
            # Each column on its own: an upgrade that stopped between the two
            # left "protocol" without "port", and was then taken for complete
            missing = [
                (name, kind) for name, kind in (("protocol", "TEXT"), ("port", "INTEGER")) if name not in columns
            ]
            if not columns or not missing:
                continue  # table not created yet, or already v3
            logger.info(f"Upgrading database schema: protocol/port columns on {table}")
            self._db.commit()
            with self._db:
                self._db.execute("BEGIN")
                for name, kind in missing:
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {kind}")

    @property
    def _db(self) -> sqlite3.Connection:
        """The open connection (connect() first)"""
        if self._connection is None:
            raise RuntimeError("Database is not connected")
        return self._connection

    def close(self):
        """Close database connection"""
        if self._connection:
            self._connection.close()
            self._connection = None

    @contextmanager
    def session(self, mode: str = "scan") -> Iterator[Optional[int]]:
        """
        Context manager for a scan session.

        Args:
            mode: Scan mode (discover, full, range)

        Yields:
            Session ID
        """
        if not self.is_enabled:
            yield None
            return

        session_id = self._start_session(mode)
        try:
            yield session_id
            self._complete_session(session_id, "completed")
        except Exception as e:
            self._complete_session(session_id, f"error: {str(e)}")
            raise

    def begin_session(self, mode: str) -> Optional[int]:
        """
        Start a scan session explicitly (for callers that cannot use the
        session() context manager). Exports made until end_session() are
        tagged with this session id.
        """
        if not self.is_enabled:
            return None
        return self._start_session(mode)

    def end_session(self, status: str = "completed") -> None:
        """Complete the session started with begin_session()"""
        if self.is_enabled and self._current_session_id is not None:
            self._complete_session(self._current_session_id, status)

    def _start_session(self, mode: str) -> int:
        """Start a new scan session"""
        cursor = self._db.execute(
            """
            INSERT INTO scan_sessions (started_at, mode, status)
            VALUES (?, ?, 'running')
            """,
            (datetime.now().isoformat(), mode),
        )
        self._db.commit()
        session_id = int(cursor.lastrowid or 0)
        self._current_session_id = session_id
        logger.debug(f"Started database session: {session_id}")
        return session_id

    def _complete_session(self, session_id: int, status: str = "completed") -> None:
        """Complete a scan session"""
        # Get statistics
        cursor = self._db.execute(
            """
            SELECT
                COUNT(DISTINCT plc_ip) as plc_count,
                SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) as error_count
            FROM data_points
            WHERE session_id = ?
            """,
            (session_id,),
        )
        stats = cursor.fetchone()

        self._db.execute(
            """
            UPDATE scan_sessions
            SET completed_at = ?, status = ?,
                plc_count = ?, success_count = ?, error_count = ?
            WHERE id = ?
            """,
            (
                datetime.now().isoformat(),
                status,
                stats["plc_count"] or 0,
                stats["success_count"] or 0,
                stats["error_count"] or 0,
                session_id,
            ),
        )
        self._db.commit()
        self._current_session_id = None
        logger.debug(f"Completed database session: {session_id}")

    def export_discovery_results(self, plc_list: List[PLCInfo], session_id: Optional[int] = None) -> int:
        """
        Export PLC discovery results.

        Args:
            plc_list: List of discovered PLCs
            session_id: Optional session ID

        Returns:
            Number of records inserted/updated
        """
        if not self.is_enabled:
            return 0

        count = 0
        now = datetime.now().isoformat()

        for plc in plc_list:
            try:
                # Upsert PLC record
                self._db.execute(
                    """
                    INSERT INTO plcs (
                        ip_address, mac_address, manufacturer, model,
                        protocol, port, cpu_type, firmware_version,
                        first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip_address, IFNULL(protocol, ''), IFNULL(port, 0)) DO UPDATE SET
                        mac_address = COALESCE(excluded.mac_address, mac_address),
                        manufacturer = COALESCE(excluded.manufacturer, manufacturer),
                        model = COALESCE(excluded.model, model),
                        cpu_type = COALESCE(excluded.cpu_type, cpu_type),
                        firmware_version = COALESCE(excluded.firmware_version, firmware_version),
                        last_seen = excluded.last_seen
                    """,
                    (
                        plc.ip_address,
                        plc.mac_address,
                        plc.manufacturer,
                        plc.model,
                        plc.protocol.name if plc.protocol else None,
                        plc.port,
                        plc.cpu_type,
                        plc.firmware_version,
                        now,
                        now,
                    ),
                )
                count += 1
            except sqlite3.OperationalError:
                # Database locked / disk full / file gone: every further row
                # would wait for the busy timeout and fail the same way.
                # Give up at once and let the caller report the failure.
                self._rollback_quietly()
                raise
            except Exception as e:
                logger.warning(f"Failed to export PLC {plc.ip_address}: {e}")

        self._db.commit()
        logger.info(f"Exported {count} PLCs to database")
        return count

    def export_plc_data(
        self,
        data_points: List[DataPoint],
        plc_ip: str,
        session_id: Optional[int] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
    ) -> int:
        """
        Export PLC data points.

        Args:
            data_points: List of data points
            plc_ip: PLC IP address
            session_id: Optional session ID
            protocol: Protocol name of the scan target (e.g. "SLMP")
            port: Port of the scan target

        Change history compares values per IP, protocol, port and address,
        so two targets sharing an IP never look like value changes.

        Returns:
            Number of records inserted
        """
        if not self.is_enabled:
            return 0

        session_id = session_id or self._current_session_id
        count = 0

        # Get previous values for history tracking
        previous_values: Dict[str, int] = {}
        target = (plc_ip, protocol, port)
        if self.config.track_history:
            if target not in self._latest_values:
                self._latest_values[target] = self._get_latest_values(plc_ip, protocol, port)
            previous_values = self._latest_values[target]

        for dp in data_points:
            try:
                # Insert data point
                self._db.execute(
                    """
                    INSERT INTO data_points (
                        session_id, plc_ip, protocol, port, address, value, raw_hex,
                        data_type, converted_value, display_value,
                        status, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        plc_ip,
                        protocol,
                        port,
                        dp.address,
                        _sqlite_integer(dp.value),
                        dp.raw_hex,
                        dp.data_type,
                        # NaN / Infinity stored as JSON null (valid JSON for any reader)
                        (
                            json.dumps(json_safe(dp.converted_value), allow_nan=False, default=str)
                            if dp.converted_value is not None
                            else None
                        ),
                        dp.display_value,
                        dp.status.value if isinstance(dp.status, StatusCode) else dp.status,
                        dp.timestamp,
                    ),
                )
                count += 1

                # Track history if value changed
                new_value = _sqlite_integer(dp.value)
                if self.config.track_history and new_value is not None:
                    old_value = previous_values.get(dp.address)
                    if old_value is not None and old_value != new_value:
                        self._record_change(plc_ip, dp.address, old_value, new_value, protocol, port)
                    previous_values[dp.address] = new_value

            except sqlite3.OperationalError:

                # Database locked / disk full / file gone: every further row

                # would wait for the busy timeout and fail the same way.

                # Give up at once and let the caller report the failure.

                self._rollback_quietly()
                # The rolled-back rows must not count as the latest values
                self._latest_values.pop(target, None)

                raise

            except Exception as e:
                logger.warning(f"Failed to export data point {dp.address}: {e}")

        self._db.commit()
        logger.debug(f"Exported {count} data points for {plc_ip}")

        # Long runs: delete expired rows once a day (no VACUUM, which would
        # block the monitoring cycle while it rewrites the whole file)
        if self._last_cleanup is not None and time.monotonic() - self._last_cleanup >= self._cleanup_interval_seconds:
            self._apply_retention(vacuum=False)
        return count

    def export_denied_addresses(
        self,
        denied_addresses: Set[str],
        plc_ip: str,
        session_id: Optional[int] = None,
        statuses: Optional[Dict[str, StatusCode]] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
    ) -> int:
        """
        Export denied addresses.

        Args:
            denied_addresses: Set of denied address strings
            plc_ip: PLC IP address
            session_id: Optional session ID
            statuses: Optional per-address status (stored instead of "DENIED")

        Returns:
            Number of records inserted
        """
        if not self.is_enabled:
            return 0

        session_id = session_id or self._current_session_id
        now = datetime.now().isoformat()
        count = 0

        for address in denied_addresses:
            try:
                self._db.execute(
                    """
                    INSERT INTO denied_addresses (
                        session_id, plc_ip, protocol, port, address, status, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        plc_ip,
                        protocol,
                        port,
                        address,
                        statuses[address].value if statuses and address in statuses else "DENIED",
                        now,
                    ),
                )
                count += 1
            except sqlite3.OperationalError:
                # Database locked / disk full / file gone: every further row
                # would wait for the busy timeout and fail the same way.
                # Give up at once and let the caller report the failure.
                self._rollback_quietly()
                raise
            except Exception as e:
                logger.warning(f"Failed to export denied address {address}: {e}")

        self._db.commit()
        return count

    def _get_latest_values(
        self, plc_ip: str, protocol: Optional[str] = None, port: Optional[int] = None
    ) -> Dict[str, int]:
        """Get the most recent value of each address of one scan target"""
        cursor = self._db.execute(
            """
            SELECT address, value
            FROM data_points
            WHERE plc_ip = ? AND protocol IS ? AND port IS ? AND value IS NOT NULL
            AND id IN (
                SELECT MAX(id) FROM data_points
                WHERE plc_ip = ? AND protocol IS ? AND port IS ?
                GROUP BY address
            )
            """,
            (plc_ip, protocol, port, plc_ip, protocol, port),
        )
        return {row["address"]: row["value"] for row in cursor}

    def _record_change(
        self,
        plc_ip: str,
        address: str,
        old_value: int,
        new_value: int,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
    ) -> None:
        """Record a value change in history"""
        self._db.execute(
            """
            INSERT INTO data_history (
                plc_ip, protocol, port, address, old_value, new_value, changed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (plc_ip, protocol, port, address, old_value, new_value, datetime.now().isoformat()),
        )

    # Query methods

    def get_plcs(self) -> List[Dict]:
        """Get all discovered PLCs"""
        if not self.is_enabled:
            return []

        cursor = self._db.execute("SELECT * FROM plcs ORDER BY last_seen DESC")
        return [dict(row) for row in cursor]

    def get_latest_data(self, plc_ip: str, limit: int = 1000) -> List[Dict]:
        """Get latest data for a PLC"""
        if not self.is_enabled:
            return []

        cursor = self._db.execute(
            """
            SELECT protocol, port, address, value, raw_hex, data_type,
                   converted_value, display_value, status, timestamp
            FROM data_points
            WHERE plc_ip = ?
            AND id IN (
                SELECT MAX(id) FROM data_points
                WHERE plc_ip = ?
                GROUP BY protocol, port, address
            )
            ORDER BY protocol, port, address
            LIMIT ?
            """,
            (plc_ip, plc_ip, limit),
        )
        return [dict(row) for row in cursor]

    def get_address_history(self, plc_ip: str, address: str, days: int = 7) -> List[Dict]:
        """
        Get historical values for an address.

        Args:
            plc_ip: PLC IP address
            address: Device address (e.g., "D100")
            days: Number of days to look back

        Returns:
            List of historical data points
        """
        if not self.is_enabled:
            return []

        cursor = self._db.execute(
            """
            SELECT protocol, port, value, raw_hex, timestamp
            FROM data_points
            WHERE plc_ip = ? AND address = ?
            AND datetime(timestamp) >= datetime('now', 'localtime', ?)
            ORDER BY timestamp DESC
            """,
            (plc_ip, address, f"-{days} days"),
        )
        return [dict(row) for row in cursor]

    def get_changes(self, plc_ip: Optional[str] = None, days: int = 7) -> List[Dict]:
        """
        Get value change history.

        Args:
            plc_ip: Optional PLC IP filter
            days: Number of days to look back

        Returns:
            List of change records
        """
        if not self.is_enabled:
            return []

        if plc_ip:
            cursor = self._db.execute(
                """
                SELECT plc_ip, protocol, port, address, old_value, new_value, changed_at
                FROM data_history
                WHERE plc_ip = ?
                AND datetime(changed_at) >= datetime('now', 'localtime', ?)
                ORDER BY changed_at DESC
                """,
                (plc_ip, f"-{days} days"),
            )
        else:
            cursor = self._db.execute(
                """
                SELECT plc_ip, protocol, port, address, old_value, new_value, changed_at
                FROM data_history
                WHERE datetime(changed_at) >= datetime('now', 'localtime', ?)
                ORDER BY changed_at DESC
                """,
                (f"-{days} days",),
            )

        return [dict(row) for row in cursor]

    def get_scan_sessions(self, limit: int = 10) -> List[Dict]:
        """Get recent scan sessions"""
        if not self.is_enabled:
            return []

        cursor = self._db.execute(
            """
            SELECT * FROM scan_sessions
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor]

    def get_statistics(self) -> Dict:
        """Get overall database statistics"""
        if not self.is_enabled:
            return {}

        stats = {}

        # PLC count
        cursor = self._db.execute("SELECT COUNT(*) FROM plcs")
        stats["total_plcs"] = cursor.fetchone()[0]

        # Data point count
        cursor = self._db.execute("SELECT COUNT(*) FROM data_points")
        stats["total_data_points"] = cursor.fetchone()[0]

        # Session count
        cursor = self._db.execute("SELECT COUNT(*) FROM scan_sessions")
        stats["total_sessions"] = cursor.fetchone()[0]

        # Change count
        cursor = self._db.execute("SELECT COUNT(*) FROM data_history")
        stats["total_changes"] = cursor.fetchone()[0]

        # Database file size
        try:
            stats["database_size_mb"] = round(Path(self.config.path).stat().st_size / (1024 * 1024), 2)
        except Exception:
            stats["database_size_mb"] = 0

        return stats

    def cleanup_old_data(self, days: Optional[int] = None) -> int:
        self._latest_values.clear()
        return self._cleanup_old_data(days)

    @property
    def _cleanup_interval_seconds(self) -> float:
        hours = self.config.cleanup_interval_hours or 0
        return hours * 3600 if hours > 0 else CLEANUP_INTERVAL_SECONDS

    def _apply_retention(self, vacuum: bool) -> None:
        """Apply max_history_days and max_size_mb (never raises)"""
        self._last_cleanup = time.monotonic()
        deleted = 0
        days = self.config.max_history_days
        try:
            if days and days > 0:
                deleted += self._cleanup_old_data(days, vacuum=False)
            deleted += self._enforce_size_limit()
            if deleted:
                logger.info(f"Database cleanup: deleted {deleted} rows")
                if vacuum:
                    # Give the freed space back to the file system (only when
                    # opening: VACUUM rewrites the whole file)
                    self._db.execute("VACUUM")
        except Exception as e:
            logger.warning(f"Database retention cleanup failed: {e}")

    def used_bytes(self) -> int:
        """Bytes of data in the database (excluding free pages)"""

        def pragma(name: str) -> int:
            return int(self._db.execute(f"PRAGMA {name}").fetchone()[0])

        return (pragma("page_count") - pragma("freelist_count")) * pragma("page_size")

    def _enforce_size_limit(self) -> int:
        """
        Delete the oldest rows until the data fits in max_size_mb.

        The latest data point of every address of every target is kept, so
        a limit that is too small cannot empty the database. Freed pages are
        reused; the file itself shrinks at the next VACUUM.

        Returns:
            Number of rows deleted
        """
        limit = float(self.config.max_size_mb or 0) * 1024 * 1024
        if limit <= 0 or not self.is_enabled:
            return 0
        deleted = 0
        while self.used_bytes() > limit:
            # Data points first: they are what fills the file. Deleting the
            # change history and the denied-address log on every pass as
            # well emptied those small tables long before the size was
            # reached. They are trimmed only when no data point is left to
            # delete (each address keeps its latest value).
            removed = self._db.execute("""DELETE FROM data_points WHERE id IN (
                       SELECT id FROM data_points
                       WHERE id NOT IN (SELECT MAX(id) FROM data_points
                                        GROUP BY plc_ip, protocol, port, address)
                       ORDER BY id LIMIT
                       (SELECT MAX(1000, COUNT(*) / 10) FROM data_points))""").rowcount
            if not removed:
                for sql in (
                    """DELETE FROM data_history WHERE id IN (
                           SELECT id FROM data_history ORDER BY id LIMIT
                           (SELECT MAX(100, COUNT(*) / 10) FROM data_history))""",
                    """DELETE FROM denied_addresses WHERE id IN (
                           SELECT id FROM denied_addresses ORDER BY id LIMIT
                           (SELECT MAX(100, COUNT(*) / 10) FROM denied_addresses))""",
                ):
                    removed += self._db.execute(sql).rowcount
            self._db.commit()
            if not removed:
                logger.warning(
                    f"Database still uses {self.used_bytes() / 1048576:.1f} MB after keeping only "
                    f"the latest values; max_size_mb ({self.config.max_size_mb}) is too small"
                )
                break
            deleted += removed
        return deleted

    def _cleanup_old_data(self, days: Optional[int] = None, vacuum: Optional[bool] = True) -> int:
        """
        Clean up old data to manage database size.

        Args:
            days: Days of data to keep (uses config if not specified)
            vacuum: True = always VACUUM, None = only when rows were
                deleted, False = never

        Returns:
            Number of rows deleted
        """
        if not self.is_enabled:
            return 0

        days = days or self.config.max_history_days
        deleted = 0

        # Delete old data points (keep latest per address)
        deleted += self._db.execute(
            """
            DELETE FROM data_points
            WHERE datetime(timestamp) < datetime('now', 'localtime', ?)
            AND id NOT IN (
                SELECT MAX(id) FROM data_points
                GROUP BY plc_ip, protocol, port, address
            )
            """,
            (f"-{days} days",),
        ).rowcount

        # Delete old history
        deleted += self._db.execute(
            """
            DELETE FROM data_history
            WHERE datetime(changed_at) < datetime('now', 'localtime', ?)
            """,
            (f"-{days} days",),
        ).rowcount

        # Delete old denied addresses
        deleted += self._db.execute(
            """
            DELETE FROM denied_addresses
            WHERE datetime(timestamp) < datetime('now', 'localtime', ?)
            """,
            (f"-{days} days",),
        ).rowcount

        # Commit the deletions first: SQLite cannot VACUUM inside a
        # transaction (the DELETEs above opened one)
        self._db.commit()

        # Vacuum to reclaim space
        if vacuum or (vacuum is None and deleted):
            self._db.execute("VACUUM")

        logger.info(f"Cleaned up data older than {days} days ({deleted} rows)")
        return deleted

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# Convenience functions


def create_database(path: str = "./plc_data.db") -> DatabaseExporter:
    """Create an enabled database exporter"""
    return DatabaseExporter.create(path)


def get_database_exporter(config: Optional[Dict] = None) -> DatabaseExporter:
    """
    Get database exporter from configuration.

    Args:
        config: Database configuration dictionary
            {
                "enabled": true,
                "path": "./plc_data.db",
                "track_history": true,
                "max_history_days": 30
            }

    Returns:
        DatabaseExporter instance
    """
    if config:
        db_config = DatabaseConfig.from_dict(config)
    else:
        db_config = DatabaseConfig(enabled=False)

    return DatabaseExporter(db_config)
