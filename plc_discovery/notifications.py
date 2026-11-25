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
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from .utils import number_text

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
    # Periodic monitoring: a target stopped answering / answers again
    PLC_UNREACHABLE = "plc_unreachable"
    PLC_RECOVERED = "plc_recovered"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    THRESHOLD_CLEARED = "threshold_cleared"
    # Periodic summary while a periodic (monitoring) scan runs
    STATUS_REPORT = "status_report"
    CUSTOM = "custom"


# Event types offered in configuration (and the GUI), with a short label
CONFIGURABLE_EVENTS = {
    NotificationType.SCAN_COMPLETE: "スキャン完了",
    NotificationType.SCAN_ERROR: "エラー（接続できないPLCなど）",
    NotificationType.DISCOVERY_COMPLETE: "探索完了",
    NotificationType.STATUS_REPORT: "周期実行中の定期報告",
    NotificationType.PLC_UNREACHABLE: "周期実行中の通信断・復旧",
    NotificationType.THRESHOLD_EXCEEDED: "周期実行中のしきい値超過・復帰",
}

# Events also delivered to destinations that chose another event: outages
# were sent as scan_error before plc_unreachable existed, and choosing
# plc_unreachable ("通信断・復旧") also brings the recovery message, and
# threshold_exceeded the message that the value is back inside
EVENT_ALSO_FOR = {
    NotificationType.PLC_UNREACHABLE: (NotificationType.SCAN_ERROR,),
    NotificationType.PLC_RECOVERED: (NotificationType.PLC_UNREACHABLE, NotificationType.SCAN_ERROR),
    NotificationType.THRESHOLD_CLEARED: (NotificationType.THRESHOLD_EXCEEDED,),
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
    # What min_interval suppression is counted per, besides the type: e.g.
    # the target, so one PLC's outage does not hide another's (not sent)
    throttle_key: Optional[str] = None

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
    # Teams message format: "adaptive" (Adaptive Card, for Teams workflow
    # webhooks) or "messagecard" (legacy Office 365 connector format)
    card_format: str = "adaptive"
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


def _urlopen_status(req: Any, timeout: float) -> int:
    """Blocking urllib POST; run via asyncio.to_thread so the event loop
    (and any PLC communication on it) is not blocked"""
    import urllib.request

    with urllib.request.urlopen(req, timeout=timeout) as response:
        return int(response.status)


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
        if event_type in self.config.events:
            return True
        return any(t in self.config.events for t in EVENT_ALSO_FOR.get(event_type, ()))

    async def _post_json(self, payload: dict, headers: Optional[Dict[str, str]] = None) -> bool:
        """
        POST payload as JSON to the configured URL, retrying up to
        retry_count times (waiting 1 s, 2 s, ... in between).

        Any 2xx answer is success. Uses aiohttp when installed, otherwise
        urllib in a worker thread (the event loop, and the PLC
        communication on it, is never blocked).
        """
        if not self.config.url:
            logger.error(f"{self.label} URL not configured ({self.config.name})")
            return False
        headers = {"Content-Type": "application/json", **(headers or {})}

        for attempt in range(self.config.retry_count):
            try:
                if AIOHTTP_AVAILABLE:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            self.config.url,
                            json=payload,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                        ) as response:
                            status = response.status
                            body = "" if _is_success(status) else await response.text()
                else:
                    import urllib.request

                    req = urllib.request.Request(
                        self.config.url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
                    )
                    status = await asyncio.to_thread(_urlopen_status, req, self.config.timeout_seconds)
                    body = ""
                if _is_success(status):
                    logger.debug(f"{self.label} sent successfully: {self.config.name}")
                    return True
                logger.warning(f"{self.label} failed: {status} {body}".rstrip())
            except Exception as e:
                logger.warning(f"{self.label} attempt {attempt + 1} failed: {e}")
            if attempt < self.config.retry_count - 1:
                await asyncio.sleep(1 * (attempt + 1))

        logger.error(f"{self.label} failed after {self.config.retry_count} attempts ({self.config.name})")
        return False

    # Name used in log messages
    label = "Notification"


class WebhookHandler(NotificationHandler):
    """HTTP Webhook notification handler (posts the event as JSON)"""

    label = "Webhook"

    async def send(self, event: NotificationEvent) -> bool:
        """Send notification via HTTP POST"""
        return await self._post_json(event.to_dict(), self.config.headers)


class SlackHandler(NotificationHandler):
    """Slack Incoming Webhook handler"""

    label = "Slack webhook"

    PRIORITY_COLORS = {
        NotificationPriority.LOW: "#36a64f",  # Green
        NotificationPriority.NORMAL: "#2196F3",  # Blue
        NotificationPriority.HIGH: "#ff9800",  # Orange
        NotificationPriority.CRITICAL: "#f44336",  # Red
    }

    def build_payload(self, event: NotificationEvent) -> dict:
        """Slack message (attachment with up to 5 extra data fields)"""
        fields = [
            {"title": "Type", "value": event.type.value, "short": True},
            {"title": "Priority", "value": event.priority.value, "short": True},
        ]
        fields += [
            {"title": key, "value": str(value), "short": True} for key, value in list((event.data or {}).items())[:5]
        ]
        return {
            "attachments": [
                {
                    "color": self.PRIORITY_COLORS.get(event.priority, "#2196F3"),
                    "title": event.title,
                    "text": event.message,
                    "fields": fields,
                    "footer": f"PLC Discovery | {event.timestamp}",
                }
            ]
        }

    async def send(self, event: NotificationEvent) -> bool:
        """Send notification to Slack"""
        return await self._post_json(self.build_payload(event))


class TeamsHandler(NotificationHandler):
    """Microsoft Teams Webhook handler"""

    label = "Teams webhook"

    PRIORITY_COLORS = {
        NotificationPriority.LOW: "00FF00",
        NotificationPriority.NORMAL: "0078D7",
        NotificationPriority.HIGH: "FFA500",
        NotificationPriority.CRITICAL: "FF0000",
    }

    # Adaptive Card text colours per priority
    ADAPTIVE_COLORS = {
        NotificationPriority.LOW: "good",
        NotificationPriority.NORMAL: "default",
        NotificationPriority.HIGH: "warning",
        NotificationPriority.CRITICAL: "attention",
    }

    @staticmethod
    def _facts(event: NotificationEvent) -> List[tuple]:
        """(name, value) pairs shown with the message: type, time, up to 5 data items"""
        facts = [("Type", event.type.value), ("Timestamp", event.timestamp)]
        facts += [(key, str(value)) for key, value in list((event.data or {}).items())[:5]]
        return facts

    def build_payload(self, event: NotificationEvent) -> dict:
        """Message for the configured format (Adaptive Card by default)"""
        if self.config.card_format == "messagecard":
            return self.build_message_card(event)
        return self.build_adaptive_card(event)

    def build_adaptive_card(self, event: NotificationEvent) -> dict:
        """
        Adaptive Card message, the format Teams workflow webhooks ("Post to
        a channel when a webhook request is received") expect; the legacy
        MessageCard is not rendered by them.
        """
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": event.title,
                                "weight": "Bolder",
                                "size": "Medium",
                                "color": self.ADAPTIVE_COLORS.get(event.priority, "default"),
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": f"Priority: {event.priority.value}",
                                "isSubtle": True,
                                "spacing": "None",
                                "wrap": True,
                            },
                            {"type": "TextBlock", "text": event.message, "wrap": True},
                            {
                                "type": "FactSet",
                                "facts": [{"title": name, "value": value} for name, value in self._facts(event)],
                            },
                        ],
                    },
                }
            ],
        }

    def build_message_card(self, event: NotificationEvent) -> dict:
        """Legacy Teams MessageCard (Office 365 connector webhooks)"""
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": self.PRIORITY_COLORS.get(event.priority, "0078D7"),
            "summary": event.title,
            "sections": [
                {
                    "activityTitle": event.title,
                    "activitySubtitle": f"Priority: {event.priority.value}",
                    "text": event.message,
                    "facts": [{"name": name, "value": value} for name, value in self._facts(event)],
                }
            ],
        }

    async def send(self, event: NotificationEvent) -> bool:
        """Send notification to Microsoft Teams"""
        return await self._post_json(self.build_payload(event))


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
            # A function without a return value has done its work: only an
            # explicit False (or an exception) reports a failed delivery
            return result is not False
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
                so a PLC failing every cycle does not flood the channel.
                Events with a throttle_key (outage, recovery, threshold) are
                counted per type and key, i.e. per target / threshold
            report_interval_seconds: how often a periodic scan sends a
                STATUS_REPORT summary (0 = never); read by the scan loops
        """
        self._handlers: Dict[str, NotificationHandler] = {}
        self.min_interval_seconds = max(0.0, float(min_interval_seconds or 0))
        self.report_interval_seconds = max(0.0, float(report_interval_seconds or 0))
        self._last_sent: Dict[Tuple[NotificationType, Optional[str]], float] = {}

    @property
    def has_handlers(self) -> bool:
        """True when at least one destination is enabled"""
        return any(h.config.enabled for h in self._handlers.values())

    def add_handler(self, config: NotificationConfig) -> None:
        """Add a notification handler"""
        handler_classes: Dict[str, Type[NotificationHandler]] = {
            "webhook": WebhookHandler,
            "slack": SlackHandler,
            "teams": TeamsHandler,
            "custom": CustomHandler,
        }
        handler_class = handler_classes.get(config.type.lower())

        if not handler_class:
            logger.error(f"Unknown notification type: {config.type}")
            return

        self._handlers[config.name] = handler_class(config)
        logger.info(f"Added notification handler: {config.name} ({config.type})")

    def add_webhook(
        self,
        name: str,
        url: str,
        events: Optional[List[NotificationType]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Convenience method to add a webhook handler"""
        config = NotificationConfig(name=name, type="webhook", url=url, events=events or [], headers=headers or {})
        self.add_handler(config)

    def add_slack(self, name: str, webhook_url: str, events: Optional[List[NotificationType]] = None) -> None:
        """Convenience method to add a Slack handler"""
        config = NotificationConfig(name=name, type="slack", url=webhook_url, events=events or [])
        self.add_handler(config)

    def add_teams(self, name: str, webhook_url: str, events: Optional[List[NotificationType]] = None) -> None:
        """Convenience method to add a Teams handler"""
        config = NotificationConfig(name=name, type="teams", url=webhook_url, events=events or [])
        self.add_handler(config)

    def add_custom(self, name: str, handler: Callable, events: Optional[List[NotificationType]] = None) -> None:
        """Add a custom handler function"""
        config = NotificationConfig(name=name, type="custom", handler=handler, events=events or [])
        self.add_handler(config)

    def remove_handler(self, name: str) -> bool:
        """Remove a notification handler"""
        if name in self._handlers:
            del self._handlers[name]
            return True
        return False

    def is_suppressed(self, event_type: NotificationType, throttle_key: Optional[str] = None) -> bool:
        """
        True while min_interval would drop this event (one with the same type
        and key was sent too recently). State-change notifications ask first
        and retry on a later cycle instead of losing the change.
        """
        last = self._last_sent.get((event_type, throttle_key))
        return (
            bool(self.min_interval_seconds) and last is not None and time.monotonic() - last < self.min_interval_seconds
        )

    @staticmethod
    def delivered(results: Any) -> bool:
        """
        False when a notify() result says every handler failed to send.
        True when at least one succeeded or no handler takes the event
        (nothing to retry).
        """
        if not isinstance(results, dict) or not results:
            return True
        return any(results.values())

    @staticmethod
    def threshold_key(target: str, condition: str) -> str:
        """The throttle key of notify_threshold"""
        return f"{target}: {condition}"

    async def notify(self, event: NotificationEvent, handlers: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Send notification to all applicable handlers.

        Args:
            event: Notification event to send
            handlers: Optional list of handler names to use

        Returns:
            Dictionary mapping handler names to success status
        """
        results: Dict[str, bool] = {}

        tasks = []
        handler_names = []

        now = time.monotonic()
        throttle = (event.type, event.throttle_key)
        if self.is_suppressed(event.type, event.throttle_key):
            about = f" for {event.throttle_key}" if event.throttle_key else ""
            logger.info(
                f"Notification '{event.type.value}'{about} suppressed: one was sent "
                f"{now - self._last_sent[throttle]:.0f}s ago (minimum interval {self.min_interval_seconds:.0f}s)"
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
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)

            for name, outcome in zip(handler_names, outcomes):
                if isinstance(outcome, BaseException):
                    logger.error(f"Handler {name} failed: {outcome}")
                    results[name] = False
                else:
                    results[name] = outcome

            # Throttle only what reached a receiver: a notification that
            # every handler failed to send must not suppress its own retry
            if any(results.values()):
                self._last_sent[throttle] = now

        return results

    async def notify_scan_complete(
        self, plc_count: int, success_count: int, error_count: int, duration_seconds: float, **extra_data: Any
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
                **extra_data,
            },
        )
        return await self.notify(event)

    async def notify_error(
        self, error_message: str, plc_ip: Optional[str] = None, **extra_data: Any
    ) -> Dict[str, bool]:
        """Send error notification"""
        event = NotificationEvent(
            type=NotificationType.SCAN_ERROR,
            title="PLC Scan Error",
            message=error_message,
            priority=NotificationPriority.HIGH,
            data={"plc_ip": plc_ip, **extra_data},
        )
        return await self.notify(event)

    async def notify_unreachable(self, target: str, plc_ip: Optional[str] = None) -> Dict[str, bool]:
        """A monitored target stopped answering (sent once per outage)"""
        event = NotificationEvent(
            type=NotificationType.PLC_UNREACHABLE,
            title="PLC Not Reachable",
            message=f"{target} is not reachable",
            priority=NotificationPriority.HIGH,
            data={"plc_ip": plc_ip, "target": target},
            throttle_key=target,
        )
        return await self.notify(event)

    async def notify_recovered(
        self, target: str, plc_ip: Optional[str] = None, downtime_seconds: float = 0.0
    ) -> Dict[str, bool]:
        """A monitored target answers again after an outage"""
        event = NotificationEvent(
            type=NotificationType.PLC_RECOVERED,
            title="PLC Reachable Again",
            message=f"{target} is reachable again (down for {downtime_seconds:.0f}s)",
            priority=NotificationPriority.NORMAL,
            data={"plc_ip": plc_ip, "target": target, "downtime_seconds": round(downtime_seconds, 1)},
            throttle_key=target,
        )
        return await self.notify(event)

    async def notify_threshold(
        self, target: str, condition: str, value: float, plc_ip: Optional[str] = None, **extra_data: Any
    ) -> Dict[str, bool]:
        """A monitored value went outside its limit (once per excursion)"""
        event = NotificationEvent(
            type=NotificationType.THRESHOLD_EXCEEDED,
            title="PLC Threshold Exceeded",
            message=f"{target}: {condition} (value {number_text(value)})",
            priority=NotificationPriority.HIGH,
            data={"plc_ip": plc_ip, "target": target, "condition": condition, "value": value, **extra_data},
            throttle_key=self.threshold_key(target, condition),
        )
        return await self.notify(event)

    async def notify_threshold_cleared(
        self,
        target: str,
        condition: str,
        value: float,
        duration_seconds: float = 0.0,
        plc_ip: Optional[str] = None,
        **extra_data: Any,
    ) -> Dict[str, bool]:
        """A notified excursion is over: the value is back inside its limit"""
        event = NotificationEvent(
            type=NotificationType.THRESHOLD_CLEARED,
            title="PLC Threshold Back to Normal",
            message=(
                f"{target}: {condition} back to normal "
                f"(value {number_text(value)}, outside for {duration_seconds:.0f}s)"
            ),
            priority=NotificationPriority.NORMAL,
            data={
                "plc_ip": plc_ip,
                "target": target,
                "condition": condition,
                "value": value,
                "duration_seconds": round(duration_seconds, 1),
                **extra_data,
            },
            throttle_key=self.threshold_key(target, condition),
        )
        return await self.notify(event)

    async def notify_discovery(
        self, plcs_found: int, plc_list: Optional[List[Dict]] = None, **extra_data: Any
    ) -> Dict[str, bool]:
        """Send discovery complete notification"""
        event = NotificationEvent(
            type=NotificationType.DISCOVERY_COMPLETE,
            title="PLC Discovery Complete",
            message=f"Discovered {plcs_found} PLC(s)",
            priority=NotificationPriority.NORMAL,
            data={"plcs_found": plcs_found, "plcs": plc_list[:5] if plc_list else [], **extra_data},  # Limit to 5
        )
        return await self.notify(event)

    async def notify_status_report(
        self, message: str, has_problems: bool = False, **extra_data: Any
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
    def from_config(cls, config: Dict) -> "NotificationManager":
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

                destination = NotificationConfig(
                    name=notif_config.get("name", "unnamed"),
                    type=notif_config.get("type", "webhook"),
                    url=notif_config.get("url") or notif_config.get("webhook_url"),
                    headers=notif_config.get("headers", {}),
                    events=events,
                    enabled=notif_config.get("enabled", True),
                    timeout_seconds=notif_config.get("timeout", 10.0),
                    retry_count=notif_config.get("retry_count", 3),
                    card_format=str(notif_config.get("format", "adaptive")).lower(),
                )
                manager.add_handler(destination)
            except Exception as e:
                logger.error(f"Failed to configure notification: {e}")

        return manager


# Global notification manager instance
_notification_manager: Optional[NotificationManager] = None


def init_notifications(config: Optional[Dict] = None) -> NotificationManager:
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
