"""
Notification Module - Webhook and Alert System

Provides notification capabilities for:
- Scan completion events
- Error alerts
- Discovery results
- Scheduled updates

Supports:
- HTTP Webhooks (POST)
- Slack Incoming Webhooks
- Microsoft Teams Webhooks
- Custom handlers
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Try to import aiohttp for async HTTP requests
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    logger.debug("aiohttp not available, using urllib for notifications")


class NotificationType(Enum):
    """Types of notifications"""
    SCAN_COMPLETE = "scan_complete"
    SCAN_ERROR = "scan_error"
    DISCOVERY_COMPLETE = "discovery_complete"
    PLC_FOUND = "plc_found"
    PLC_UNREACHABLE = "plc_unreachable"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    # Periodic summary while a periodic (monitoring) scan runs
    STATUS_REPORT = "status_report"
    CUSTOM = "custom"


# Event types offered in configuration (and the GUI), with a short label
CONFIGURABLE_EVENTS = {
    NotificationType.SCAN_COMPLETE: "スキャン完了",
    NotificationType.SCAN_ERROR: "エラー（接続できないPLCなど）",
    NotificationType.DISCOVERY_COMPLETE: "探索完了",
    NotificationType.STATUS_REPORT: "周期実行中の定期報告",
}

# Notification destination types offered in configuration
NOTIFICATION_TYPES = ("webhook", "slack", "teams")


class NotificationPriority(Enum):
    """Notification priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NotificationEvent:
    """Represents a notification event"""
    type: NotificationType
    title: str
    message: str
    priority: NotificationPriority = NotificationPriority.NORMAL
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = "plc_discovery"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "type": self.type.value,
            "title": self.title,
            "message": self.message,
            "priority": self.priority.value,
            "timestamp": self.timestamp,
            "data": self.data,
            "source": self.source,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class NotificationConfig:
    """Configuration for a notification handler"""
    name: str
    type: str  # "webhook", "slack", "teams", "custom"
    url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    events: List[NotificationType] = field(default_factory=list)
    enabled: bool = True
    timeout_seconds: float = 10.0
    retry_count: int = 3
    # Custom handler function (for type="custom")
    handler: Optional[Callable] = None


def _is_success(status: int) -> bool:
    """
    Any 2xx answer means the message was accepted. Teams webhooks created
    with Power Automate workflows (which replace the retired Office 365
    connectors) answer 202: checking for 200 only made every message be
    re-sent retry_count times and logged as failed.
    """
    return 200 <= status < 300


def _urlopen_status(req, timeout: float) -> int:
    """Blocking urllib POST; run via asyncio.to_thread so the event loop
    (and any PLC communication on it) is not blocked"""
    import urllib.request
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status


class NotificationHandler(ABC):
    """Abstract base class for notification handlers"""
    
    def __init__(self, config: NotificationConfig):
        self.config = config
    
    @abstractmethod
    async def send(self, event: NotificationEvent) -> bool:
        """
        Send notification.
        
        Args:
            event: Notification event to send
        
        Returns:
            True if successful, False otherwise
        """
        pass
    
    def should_handle(self, event_type: NotificationType) -> bool:
        """Check if this handler should handle the event type"""
        if not self.config.enabled:
            return False
        if not self.config.events:
            return True  # Handle all if no specific types configured
        return event_type in self.config.events


class WebhookHandler(NotificationHandler):
    """HTTP Webhook notification handler"""
    
    async def send(self, event: NotificationEvent) -> bool:
        """Send notification via HTTP POST"""
        if not self.config.url:
            logger.error("Webhook URL not configured")
            return False
        
        headers = {
            "Content-Type": "application/json",
            **self.config.headers
        }
        
        payload = event.to_dict()
        
        for attempt in range(self.config.retry_count):
            try:
                if AIOHTTP_AVAILABLE:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            self.config.url,
                            json=payload,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
                        ) as response:
                            if response.status < 400:
                                logger.debug(f"Webhook sent successfully: {self.config.name}")
                                return True
                            else:
                                logger.warning(
                                    f"Webhook failed: {response.status} - {await response.text()}"
                                )
                else:
                    # Fallback to urllib
                    import urllib.request
                    import urllib.error
                    
                    req = urllib.request.Request(
                        self.config.url,
                        data=json.dumps(payload).encode('utf-8'),
                        headers=headers,
                        method='POST'
                    )
                    
                    status = await asyncio.to_thread(_urlopen_status, req, self.config.timeout_seconds)
                    if status < 400:
                        logger.debug(f"Webhook sent successfully: {self.config.name}")
                        return True

            except Exception as e:
                logger.warning(f"Webhook attempt {attempt + 1} failed: {e}")
                if attempt < self.config.retry_count - 1:
                    await asyncio.sleep(1 * (attempt + 1))
        
        logger.error(f"Webhook failed after {self.config.retry_count} attempts")
        return False


class SlackHandler(NotificationHandler):
    """Slack Incoming Webhook handler"""
    
    PRIORITY_COLORS = {
        NotificationPriority.LOW: "#36a64f",      # Green
        NotificationPriority.NORMAL: "#2196F3",   # Blue
        NotificationPriority.HIGH: "#ff9800",     # Orange
        NotificationPriority.CRITICAL: "#f44336", # Red
    }
    
    async def send(self, event: NotificationEvent) -> bool:
        """Send notification to Slack"""
        if not self.config.url:
            logger.error("Slack webhook URL not configured")
            return False
        
        # Build Slack message format
        color = self.PRIORITY_COLORS.get(event.priority, "#2196F3")
        
        slack_payload = {
            "attachments": [{
                "color": color,
                "title": event.title,
                "text": event.message,
                "fields": [
                    {"title": "Type", "value": event.type.value, "short": True},
                    {"title": "Priority", "value": event.priority.value, "short": True},
                ],
                "footer": f"PLC Discovery | {event.timestamp}",
            }]
        }
        
        # Add extra data fields
        if event.data:
            for key, value in list(event.data.items())[:5]:  # Limit to 5 fields
                slack_payload["attachments"][0]["fields"].append({
                    "title": key,
                    "value": str(value),
                    "short": True
                })
        
        return await self._send_request(slack_payload)
    
    async def _send_request(self, payload: dict) -> bool:
        """Send request to Slack"""
        for attempt in range(self.config.retry_count):
            try:
                if AIOHTTP_AVAILABLE:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            self.config.url,
                            json=payload,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
                        ) as response:
                            if _is_success(response.status):
                                return True
                            else:
                                logger.warning(f"Slack webhook failed: {response.status}")
                else:
                    import urllib.request
                    req = urllib.request.Request(
                        self.config.url,
                        data=json.dumps(payload).encode('utf-8'),
                        headers={"Content-Type": "application/json"},
                        method='POST'
                    )
                    status = await asyncio.to_thread(_urlopen_status, req, self.config.timeout_seconds)
                    if _is_success(status):
                        return True
                            
            except Exception as e:
                logger.warning(f"Slack attempt {attempt + 1} failed: {e}")
                if attempt < self.config.retry_count - 1:
                    await asyncio.sleep(1)
        
        return False


class TeamsHandler(NotificationHandler):
    """Microsoft Teams Webhook handler"""
    
    PRIORITY_COLORS = {
        NotificationPriority.LOW: "00FF00",
        NotificationPriority.NORMAL: "0078D7",
        NotificationPriority.HIGH: "FFA500",
        NotificationPriority.CRITICAL: "FF0000",
    }
    
    async def send(self, event: NotificationEvent) -> bool:
        """Send notification to Microsoft Teams"""
        if not self.config.url:
            logger.error("Teams webhook URL not configured")
            return False
        
        color = self.PRIORITY_COLORS.get(event.priority, "0078D7")
        
        # Build Teams Adaptive Card format
        teams_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": event.title,
            "sections": [{
                "activityTitle": event.title,
                "activitySubtitle": f"Priority: {event.priority.value}",
                "text": event.message,
                "facts": [
                    {"name": "Type", "value": event.type.value},
                    {"name": "Timestamp", "value": event.timestamp},
                ],
            }]
        }
        
        # Add extra data
        if event.data:
            for key, value in list(event.data.items())[:5]:
                teams_payload["sections"][0]["facts"].append({
                    "name": key,
                    "value": str(value)
                })
        
        return await self._send_request(teams_payload)
    
    async def _send_request(self, payload: dict) -> bool:
        """Send request to Teams"""
        for attempt in range(self.config.retry_count):
            try:
                if AIOHTTP_AVAILABLE:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            self.config.url,
                            json=payload,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
                        ) as response:
                            if _is_success(response.status):
                                return True
                            logger.warning(f"Teams webhook failed: {response.status}")
                else:
                    import urllib.request
                    req = urllib.request.Request(
                        self.config.url,
                        data=json.dumps(payload).encode('utf-8'),
                        headers={"Content-Type": "application/json"},
                        method='POST'
                    )
                    status = await asyncio.to_thread(_urlopen_status, req, self.config.timeout_seconds)
                    if _is_success(status):
                        return True
                            
            except Exception as e:
                logger.warning(f"Teams attempt {attempt + 1} failed: {e}")
                if attempt < self.config.retry_count - 1:
                    await asyncio.sleep(1)
        
        return False


class CustomHandler(NotificationHandler):
    """Custom notification handler using user-provided function"""
    
    async def send(self, event: NotificationEvent) -> bool:
        """Call custom handler function"""
        if not self.config.handler:
            logger.error("Custom handler function not configured")
            return False
        
        try:
            result = self.config.handler(event)
            if asyncio.iscoroutine(result):
                result = await result
            return bool(result)
        except Exception as e:
            logger.error(f"Custom handler error: {e}")
            return False


class NotificationManager:
    """
    Manages multiple notification handlers and dispatches events.
    
    Usage:
        manager = NotificationManager()
        manager.add_webhook("alerts", "https://example.com/webhook")
        manager.add_slack("slack", "https://hooks.slack.com/...")
        
        await manager.notify(NotificationEvent(
            type=NotificationType.SCAN_COMPLETE,
            title="Scan Complete",
            message="Scanned 10 PLCs successfully"
        ))
    """
    
    def __init__(self, min_interval_seconds: float = 0, report_interval_seconds: float = 0):
        """
        Args:
            min_interval_seconds: an event type is sent at most once in this
                many seconds; repeats in between are dropped (0 = no limit),
                so a PLC failing every cycle does not flood the channel
            report_interval_seconds: how often a periodic scan sends a
                STATUS_REPORT summary (0 = never); read by the scan loops
        """
        self._handlers: Dict[str, NotificationHandler] = {}
        self.min_interval_seconds = max(0.0, float(min_interval_seconds or 0))
        self.report_interval_seconds = max(0.0, float(report_interval_seconds or 0))
        self._last_sent: Dict[NotificationType, float] = {}
    
    @property
    def has_handlers(self) -> bool:
        """True when at least one destination is enabled"""
        return any(h.config.enabled for h in self._handlers.values())
    
    def add_handler(self, config: NotificationConfig) -> None:
        """Add a notification handler"""
        handler_class = {
            "webhook": WebhookHandler,
            "slack": SlackHandler,
            "teams": TeamsHandler,
            "custom": CustomHandler,
        }.get(config.type.lower())
        
        if not handler_class:
            logger.error(f"Unknown notification type: {config.type}")
            return
        
        self._handlers[config.name] = handler_class(config)
        logger.info(f"Added notification handler: {config.name} ({config.type})")
    
    def add_webhook(
        self,
        name: str,
        url: str,
        events: List[NotificationType] = None,
        headers: Dict[str, str] = None
    ) -> None:
        """Convenience method to add a webhook handler"""
        config = NotificationConfig(
            name=name,
            type="webhook",
            url=url,
            events=events or [],
            headers=headers or {}
        )
        self.add_handler(config)
    
    def add_slack(
        self,
        name: str,
        webhook_url: str,
        events: List[NotificationType] = None
    ) -> None:
        """Convenience method to add a Slack handler"""
        config = NotificationConfig(
            name=name,
            type="slack",
            url=webhook_url,
            events=events or []
        )
        self.add_handler(config)
    
    def add_teams(
        self,
        name: str,
        webhook_url: str,
        events: List[NotificationType] = None
    ) -> None:
        """Convenience method to add a Teams handler"""
        config = NotificationConfig(
            name=name,
            type="teams",
            url=webhook_url,
            events=events or []
        )
        self.add_handler(config)
    
    def add_custom(
        self,
        name: str,
        handler: Callable,
        events: List[NotificationType] = None
    ) -> None:
        """Add a custom handler function"""
        config = NotificationConfig(
            name=name,
            type="custom",
            handler=handler,
            events=events or []
        )
        self.add_handler(config)
    
    def remove_handler(self, name: str) -> bool:
        """Remove a notification handler"""
        if name in self._handlers:
            del self._handlers[name]
            return True
        return False
    
    async def notify(
        self,
        event: NotificationEvent,
        handlers: List[str] = None
    ) -> Dict[str, bool]:
        """
        Send notification to all applicable handlers.
        
        Args:
            event: Notification event to send
            handlers: Optional list of handler names to use
        
        Returns:
            Dictionary mapping handler names to success status
        """
        results = {}
        
        tasks = []
        handler_names = []
        
        now = time.monotonic()
        last = self._last_sent.get(event.type)
        if self.min_interval_seconds and last is not None and now - last < self.min_interval_seconds:
            logger.info(
                f"Notification '{event.type.value}' suppressed: one was sent "
                f"{now - last:.0f}s ago (minimum interval {self.min_interval_seconds:.0f}s)"
            )
            return results
        
        for name, handler in self._handlers.items():
            # Filter by specific handlers if provided
            if handlers and name not in handlers:
                continue
            
            # Check if handler should handle this event type
            if not handler.should_handle(event.type):
                continue
            
            tasks.append(handler.send(event))
            handler_names.append(name)
        
        if tasks:
            self._last_sent[event.type] = now
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            
            for name, outcome in zip(handler_names, outcomes):
                if isinstance(outcome, Exception):
                    logger.error(f"Handler {name} failed: {outcome}")
                    results[name] = False
                else:
                    results[name] = outcome
        
        return results
    
    async def notify_scan_complete(
        self,
        plc_count: int,
        success_count: int,
        error_count: int,
        duration_seconds: float,
        **extra_data
    ) -> Dict[str, bool]:
        """Send scan complete notification"""
        event = NotificationEvent(
            type=NotificationType.SCAN_COMPLETE,
            title="PLC Scan Complete",
            message=f"Scanned {plc_count} PLCs: {success_count} successful, {error_count} errors",
            priority=NotificationPriority.NORMAL if error_count == 0 else NotificationPriority.HIGH,
            data={
                "plc_count": plc_count,
                "success_count": success_count,
                "error_count": error_count,
                "duration_seconds": round(duration_seconds, 2),
                **extra_data
            }
        )
        return await self.notify(event)
    
    async def notify_error(
        self,
        error_message: str,
        plc_ip: str = None,
        **extra_data
    ) -> Dict[str, bool]:
        """Send error notification"""
        event = NotificationEvent(
            type=NotificationType.SCAN_ERROR,
            title="PLC Scan Error",
            message=error_message,
            priority=NotificationPriority.HIGH,
            data={
                "plc_ip": plc_ip,
                **extra_data
            }
        )
        return await self.notify(event)
    
    async def notify_discovery(
        self,
        plcs_found: int,
        plc_list: List[Dict] = None,
        **extra_data
    ) -> Dict[str, bool]:
        """Send discovery complete notification"""
        event = NotificationEvent(
            type=NotificationType.DISCOVERY_COMPLETE,
            title="PLC Discovery Complete",
            message=f"Discovered {plcs_found} PLC(s)",
            priority=NotificationPriority.NORMAL,
            data={
                "plcs_found": plcs_found,
                "plcs": plc_list[:5] if plc_list else [],  # Limit to 5
                **extra_data
            }
        )
        return await self.notify(event)
    
    async def notify_status_report(
        self,
        message: str,
        has_problems: bool = False,
        **extra_data
    ) -> Dict[str, bool]:
        """Send a periodic status report (summary of a monitoring run)"""
        event = NotificationEvent(
            type=NotificationType.STATUS_REPORT,
            title="PLC Monitoring Status",
            message=message,
            priority=NotificationPriority.HIGH if has_problems else NotificationPriority.LOW,
            data=extra_data,
        )
        return await self.notify(event)
    
    @classmethod
    def from_config(cls, config: Dict) -> 'NotificationManager':
        """
        Create NotificationManager from configuration dictionary.
        
        Config format:
            notifications:
              - name: my_webhook
                type: webhook
                url: https://example.com/webhook
                events: [scan_complete, scan_error]
              - name: slack_alerts
                type: slack
                url: https://hooks.slack.com/...
        """
        settings = config.get("notification_settings") or {}
        manager = cls(
            min_interval_seconds=60 * float(settings.get("min_interval_minutes", 0) or 0),
            report_interval_seconds=60 * float(settings.get("report_interval_minutes", 0) or 0),
        )
        
        notifications = config.get("notifications", []) or []
        for notif_config in notifications:
            try:
                # Parse events
                events = []
                for event_str in notif_config.get("events", []):
                    try:
                        events.append(NotificationType(event_str))
                    except ValueError:
                        logger.warning(f"Unknown event type: {event_str}")
                
                config = NotificationConfig(
                    name=notif_config.get("name", "unnamed"),
                    type=notif_config.get("type", "webhook"),
                    url=notif_config.get("url") or notif_config.get("webhook_url"),
                    headers=notif_config.get("headers", {}),
                    events=events,
                    enabled=notif_config.get("enabled", True),
                    timeout_seconds=notif_config.get("timeout", 10.0),
                    retry_count=notif_config.get("retry_count", 3),
                )
                manager.add_handler(config)
            except Exception as e:
                logger.error(f"Failed to configure notification: {e}")
        
        return manager


# Global notification manager instance
_notification_manager: Optional[NotificationManager] = None


def init_notifications(config: Dict = None) -> NotificationManager:
    """Initialize global notification manager"""
    global _notification_manager
    
    if config:
        _notification_manager = NotificationManager.from_config(config)
    else:
        _notification_manager = NotificationManager()
    
    return _notification_manager


def get_notification_manager() -> Optional[NotificationManager]:
    """Get global notification manager instance"""
    return _notification_manager


async def notify(event: NotificationEvent) -> Dict[str, bool]:
    """Send notification using global manager"""
    if _notification_manager:
        return await _notification_manager.notify(event)
    return {}


