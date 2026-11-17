"""
Unit tests for notifications module
"""

from unittest.mock import AsyncMock, patch

import pytest

from plc_discovery.notifications import (
    CustomHandler,
    NotificationConfig,
    NotificationEvent,
    NotificationManager,
    NotificationPriority,
    NotificationType,
    WebhookHandler,
    get_notification_manager,
    init_notifications,
)


class TestNotificationEvent:
    """Test NotificationEvent class"""

    def test_event_creation(self):
        """Test creating a notification event"""
        event = NotificationEvent(type=NotificationType.SCAN_COMPLETE, title="Test Title", message="Test message")

        assert event.type == NotificationType.SCAN_COMPLETE
        assert event.title == "Test Title"
        assert event.message == "Test message"
        assert event.priority == NotificationPriority.NORMAL
        assert event.source == "plc_discovery"

    def test_event_to_dict(self):
        """Test converting event to dictionary"""
        event = NotificationEvent(
            type=NotificationType.SCAN_ERROR,
            title="Error",
            message="Something went wrong",
            priority=NotificationPriority.HIGH,
            data={"plc_ip": "192.168.1.10"},
        )

        result = event.to_dict()

        assert result["type"] == "scan_error"
        assert result["title"] == "Error"
        assert result["message"] == "Something went wrong"
        assert result["priority"] == "high"
        assert result["data"]["plc_ip"] == "192.168.1.10"

    def test_event_to_json(self):
        """Test converting event to JSON"""
        event = NotificationEvent(type=NotificationType.DISCOVERY_COMPLETE, title="Discovery", message="Found 5 PLCs")

        json_str = event.to_json()

        assert '"type": "discovery_complete"' in json_str
        assert '"title": "Discovery"' in json_str


class TestNotificationConfig:
    """Test NotificationConfig class"""

    def test_default_config(self):
        """Test default configuration values"""
        config = NotificationConfig(name="test", type="webhook", url="https://example.com/webhook")

        assert config.name == "test"
        assert config.type == "webhook"
        assert config.enabled is True
        assert config.timeout_seconds == 10.0
        assert config.retry_count == 3

    def test_config_with_events(self):
        """Test configuration with specific events"""
        config = NotificationConfig(
            name="test",
            type="slack",
            url="https://hooks.slack.com/...",
            events=[NotificationType.SCAN_COMPLETE, NotificationType.SCAN_ERROR],
        )

        assert len(config.events) == 2
        assert NotificationType.SCAN_COMPLETE in config.events


class TestWebhookHandler:
    """Test WebhookHandler class"""

    @pytest.mark.asyncio
    async def test_should_handle_all_events(self):
        """Test handler with no specific events handles all"""
        config = NotificationConfig(name="test", type="webhook", url="https://example.com")
        handler = WebhookHandler(config)

        assert handler.should_handle(NotificationType.SCAN_COMPLETE)
        assert handler.should_handle(NotificationType.SCAN_ERROR)

    @pytest.mark.asyncio
    async def test_should_handle_specific_events(self):
        """Test handler with specific events"""
        config = NotificationConfig(
            name="test", type="webhook", url="https://example.com", events=[NotificationType.SCAN_COMPLETE]
        )
        handler = WebhookHandler(config)

        assert handler.should_handle(NotificationType.SCAN_COMPLETE)
        assert not handler.should_handle(NotificationType.SCAN_ERROR)

    @pytest.mark.asyncio
    async def test_disabled_handler(self):
        """Test disabled handler"""
        config = NotificationConfig(name="test", type="webhook", url="https://example.com", enabled=False)
        handler = WebhookHandler(config)

        assert not handler.should_handle(NotificationType.SCAN_COMPLETE)

    @pytest.mark.asyncio
    async def test_send_without_url(self):
        """Test send fails without URL"""
        config = NotificationConfig(name="test", type="webhook")
        handler = WebhookHandler(config)

        event = NotificationEvent(type=NotificationType.SCAN_COMPLETE, title="Test", message="Test")

        result = await handler.send(event)
        assert result is False


class TestNotificationManager:
    """Test NotificationManager class"""

    def test_add_webhook(self):
        """Test adding webhook handler"""
        manager = NotificationManager()
        manager.add_webhook("test", "https://example.com/webhook")

        assert "test" in manager._handlers

    def test_add_slack(self):
        """Test adding Slack handler"""
        manager = NotificationManager()
        manager.add_slack("slack", "https://hooks.slack.com/...")

        assert "slack" in manager._handlers

    def test_add_teams(self):
        """Test adding Teams handler"""
        manager = NotificationManager()
        manager.add_teams("teams", "https://outlook.office.com/webhook/...")

        assert "teams" in manager._handlers

    def test_add_custom(self):
        """Test adding custom handler"""
        manager = NotificationManager()

        def custom_handler(event):
            return True

        manager.add_custom("custom", custom_handler)

        assert "custom" in manager._handlers

    def test_remove_handler(self):
        """Test removing handler"""
        manager = NotificationManager()
        manager.add_webhook("test", "https://example.com")

        result = manager.remove_handler("test")
        assert result is True
        assert "test" not in manager._handlers

        result = manager.remove_handler("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_notify_no_handlers(self):
        """Test notify with no handlers"""
        manager = NotificationManager()

        event = NotificationEvent(type=NotificationType.SCAN_COMPLETE, title="Test", message="Test")

        results = await manager.notify(event)
        assert results == {}

    @pytest.mark.asyncio
    async def test_notify_scan_complete(self):
        """Test notify_scan_complete convenience method"""
        manager = NotificationManager()

        with patch.object(manager, "notify", new_callable=AsyncMock) as mock_notify:
            mock_notify.return_value = {"test": True}

            await manager.notify_scan_complete(plc_count=5, success_count=4, error_count=1, duration_seconds=30.5)

            mock_notify.assert_called_once()
            call_args = mock_notify.call_args[0][0]
            assert call_args.type == NotificationType.SCAN_COMPLETE
            assert "5" in call_args.message

    @pytest.mark.asyncio
    async def test_notify_error(self):
        """Test notify_error convenience method"""
        manager = NotificationManager()

        with patch.object(manager, "notify", new_callable=AsyncMock) as mock_notify:
            mock_notify.return_value = {"test": True}

            await manager.notify_error(error_message="Connection failed", plc_ip="192.168.1.10")

            mock_notify.assert_called_once()
            call_args = mock_notify.call_args[0][0]
            assert call_args.type == NotificationType.SCAN_ERROR
            assert call_args.priority == NotificationPriority.HIGH

    def test_from_config(self):
        """Test creating manager from config dictionary"""
        config = {
            "notifications": [
                {
                    "name": "webhook1",
                    "type": "webhook",
                    "url": "https://example.com/webhook",
                    "events": ["scan_complete"],
                },
                {"name": "slack1", "type": "slack", "url": "https://hooks.slack.com/...", "enabled": False},
            ]
        }

        manager = NotificationManager.from_config(config)

        assert "webhook1" in manager._handlers
        assert "slack1" in manager._handlers


class TestCustomHandler:
    """Test CustomHandler class"""

    @pytest.mark.asyncio
    async def test_sync_handler(self):
        """Test custom sync handler"""

        def handler(event):
            return True

        config = NotificationConfig(name="test", type="custom", handler=handler)
        custom = CustomHandler(config)

        event = NotificationEvent(type=NotificationType.SCAN_COMPLETE, title="Test", message="Test")

        result = await custom.send(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_async_handler(self):
        """Test custom async handler"""

        async def handler(event):
            return True

        config = NotificationConfig(name="test", type="custom", handler=handler)
        custom = CustomHandler(config)

        event = NotificationEvent(type=NotificationType.SCAN_COMPLETE, title="Test", message="Test")

        result = await custom.send(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_handler_error(self):
        """Test custom handler error handling"""

        def handler(event):
            raise ValueError("Test error")

        config = NotificationConfig(name="test", type="custom", handler=handler)
        custom = CustomHandler(config)

        event = NotificationEvent(type=NotificationType.SCAN_COMPLETE, title="Test", message="Test")

        result = await custom.send(event)
        assert result is False


class TestGlobalFunctions:
    """Test global notification functions"""

    def test_init_notifications(self):
        """Test init_notifications function"""
        config = {"notifications": [{"name": "test", "type": "webhook", "url": "https://example.com"}]}

        manager = init_notifications(config)

        assert manager is not None
        assert "test" in manager._handlers

    def test_get_notification_manager(self):
        """Test get_notification_manager function"""
        init_notifications()
        manager = get_notification_manager()

        assert manager is not None
