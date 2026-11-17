"""
PLC Discovery Tool - Factory PLC Auto-Detection and Data Collection

A multi-vendor PLC automatic discovery and data collection tool
for factory maintenance and diagnostics.
"""

__version__ = "1.4.0"
__author__ = "PLC Discovery Team"

# Core modules
from .config import (
    Protocol, DeviceType, ScanMode, StatusCode,
    PLCInfo, DataPoint, DeviceRange, NetworkConfig,
)
from .discovery import PLCDiscovery, discover_plcs
from .collector import PLCDataCollector, collect_plc_data
from .output import CSVExporter

# Report generation (v1.4)
from .report import (
    ReportGenerator, ReportConfig, ReportFormat,
    ReportData, ScanSummary,
    create_report, generate_html_report, generate_pdf_report,
)

# New modules (v1.1)
from .config_loader import ConfigLoader, load_config, generate_config_template
from .audit_log import (
    AuditLogger, AuditEvent, AuditEventType,
    init_audit_logger, get_audit_logger, close_audit_logger,
)
from .parallel import ParallelPLCScanner, PLCScanResult, scan_plcs_parallel
from .broadcast_discovery import BroadcastDiscovery, discover_broadcast
from .progress import RichProgressDisplay, get_display, is_rich_available

# Data type conversion (v1.2)
from .data_types import (
    DataType, ByteOrder, TypedValue, DataTypeConverter,
    DataTypeMapping, DataTypeManager,
)

# Retry and error handling (v1.3)
from .retry import (
    RetryConfig, RetryStrategy, RetryHandler, RetryError,
    CircuitBreaker, CircuitBreakerConfig, CircuitState,
    with_retry, with_retry_sync,
    DEFAULT_RETRY_CONFIG, AGGRESSIVE_RETRY_CONFIG,
    CONSERVATIVE_RETRY_CONFIG, PLC_RETRY_CONFIG,
)

# Notifications (v1.3)
from .notifications import (
    NotificationManager, NotificationEvent, NotificationType,
    NotificationPriority, NotificationConfig,
    WebhookHandler, SlackHandler, TeamsHandler,
    init_notifications, get_notification_manager, notify,
)

# Database output (v1.3)
from .database import (
    DatabaseExporter, DatabaseConfig,
    create_database, get_database_exporter,
)

__all__ = [
    # Version
    "__version__",
    "__author__",

    # Config
    "Protocol",
    "DeviceType",
    "ScanMode",
    "StatusCode",
    "PLCInfo",
    "DataPoint",
    "DeviceRange",
    "NetworkConfig",

    # Discovery
    "PLCDiscovery",
    "discover_plcs",
    "BroadcastDiscovery",
    "discover_broadcast",

    # Collection
    "PLCDataCollector",
    "collect_plc_data",
    "ParallelPLCScanner",
    "PLCScanResult",
    "scan_plcs_parallel",

    # Output
    "CSVExporter",

    # Report
    "ReportGenerator",
    "ReportConfig",
    "ReportFormat",
    "ReportData",
    "ScanSummary",
    "create_report",
    "generate_html_report",
    "generate_pdf_report",

    # Configuration
    "ConfigLoader",
    "load_config",
    "generate_config_template",

    # Audit
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "init_audit_logger",
    "get_audit_logger",
    "close_audit_logger",

    # Progress
    "RichProgressDisplay",
    "get_display",
    "is_rich_available",

    # Data Types
    "DataType",
    "ByteOrder",
    "TypedValue",
    "DataTypeConverter",
    "DataTypeMapping",
    "DataTypeManager",

    # Retry
    "RetryConfig",
    "RetryStrategy",
    "RetryHandler",
    "RetryError",
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitState",
    "with_retry",
    "with_retry_sync",
    "DEFAULT_RETRY_CONFIG",
    "AGGRESSIVE_RETRY_CONFIG",
    "CONSERVATIVE_RETRY_CONFIG",
    "PLC_RETRY_CONFIG",

    # Notifications
    "NotificationManager",
    "NotificationEvent",
    "NotificationType",
    "NotificationPriority",
    "NotificationConfig",
    "WebhookHandler",
    "SlackHandler",
    "TeamsHandler",
    "init_notifications",
    "get_notification_manager",
    "notify",

    # Database
    "DatabaseExporter",
    "DatabaseConfig",
    "create_database",
    "get_database_exporter",
]
