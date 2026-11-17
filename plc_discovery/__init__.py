"""
PLC Discovery Tool - Factory PLC Auto-Detection and Data Collection

A multi-vendor PLC automatic discovery and data collection tool
for factory maintenance and diagnostics.
"""

__version__ = "1.4.0"
__author__ = "PLC Discovery Team"

from .audit_log import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    close_audit_logger,
    get_audit_logger,
    init_audit_logger,
)
from .broadcast_discovery import BroadcastDiscovery, discover_broadcast
from .collector import PLCDataCollector, collect_plc_data

# Core modules
from .config import (
    DataPoint,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    PLCInfo,
    Protocol,
    ScanMode,
    StatusCode,
)

# New modules (v1.1)
from .config_loader import ConfigLoader, generate_config_template, load_config

# Data type conversion (v1.2)
from .data_types import (
    ByteOrder,
    DataType,
    DataTypeConverter,
    DataTypeManager,
    DataTypeMapping,
    TypedValue,
)

# Database output (v1.3)
from .database import (
    DatabaseConfig,
    DatabaseExporter,
    create_database,
    get_database_exporter,
)
from .discovery import PLCDiscovery, discover_plcs

# Notifications (v1.3)
from .notifications import (
    NotificationConfig,
    NotificationEvent,
    NotificationManager,
    NotificationPriority,
    NotificationType,
    SlackHandler,
    TeamsHandler,
    WebhookHandler,
    get_notification_manager,
    init_notifications,
    notify,
)
from .output import CSVExporter
from .parallel import ParallelPLCScanner, PLCScanResult, scan_plcs_parallel
from .progress import RichProgressDisplay, get_display, is_rich_available

# Report generation (v1.4)
from .report import (
    ReportConfig,
    ReportData,
    ReportFormat,
    ReportGenerator,
    ScanSummary,
    create_report,
    generate_html_report,
    generate_pdf_report,
)

# Retry and error handling (v1.3)
from .retry import (
    AGGRESSIVE_RETRY_CONFIG,
    CONSERVATIVE_RETRY_CONFIG,
    DEFAULT_RETRY_CONFIG,
    PLC_RETRY_CONFIG,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    RetryConfig,
    RetryError,
    RetryHandler,
    RetryStrategy,
    with_retry,
    with_retry_sync,
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
