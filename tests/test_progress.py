"""
Tests for progress module
"""


from plc_discovery.progress import (
    SimpleProgress, RichProgressDisplay,
    get_display, is_rich_available, create_progress_callback
)


class TestSimpleProgress:
    """Tests for SimpleProgress fallback class"""

    def test_update_with_total(self, capsys):
        """Test update with total for percentage"""
        progress = SimpleProgress()
        progress._last_update = 0  # Reset rate limit

        progress.update("Processing", 50, 100)

        captured = capsys.readouterr()
        assert "50" in captured.out or "Processing" in captured.out

    def test_update_without_total(self, capsys):
        """Test update without total"""
        progress = SimpleProgress()
        progress._last_update = 0

        progress.update("Loading")

        captured = capsys.readouterr()
        assert "Loading" in captured.out

    def test_complete(self, capsys):
        """Test complete message"""
        progress = SimpleProgress()

        progress.complete("Done!")

        captured = capsys.readouterr()
        assert "Done!" in captured.out

    def test_error(self, capsys):
        """Test error message"""
        progress = SimpleProgress()

        progress.error("Failed!")

        captured = capsys.readouterr()
        assert "Failed!" in captured.out


class TestRichProgressDisplay:
    """Tests for RichProgressDisplay class"""

    def test_init(self):
        """Test initialization"""
        display = RichProgressDisplay("Test Title")

        assert display.title == "Test Title"

    def test_print_without_rich(self, capsys):
        """Test print falls back gracefully without rich"""
        display = RichProgressDisplay()
        display.console = None  # Force non-rich mode

        display.print("Test message")

        captured = capsys.readouterr()
        assert "Test message" in captured.out

    def test_print_header_without_rich(self, capsys):
        """Test print_header without rich"""
        display = RichProgressDisplay()
        display.console = None

        display.print_header()

        captured = capsys.readouterr()
        assert "PLC Discovery Tool" in captured.out

    def test_print_error(self, capsys):
        """Test print_error"""
        display = RichProgressDisplay()
        display.console = None

        display.print_error("Something went wrong")

        captured = capsys.readouterr()
        assert "Error" in captured.out
        assert "Something went wrong" in captured.out

    def test_print_warning(self, capsys):
        """Test print_warning"""
        display = RichProgressDisplay()
        display.console = None

        display.print_warning("Be careful")

        captured = capsys.readouterr()
        assert "Warning" in captured.out
        assert "Be careful" in captured.out

    def test_print_success(self, capsys):
        """Test print_success"""
        display = RichProgressDisplay()
        display.console = None

        display.print_success("Task completed")

        captured = capsys.readouterr()
        assert "Task completed" in captured.out

    def test_print_info(self, capsys):
        """Test print_info"""
        display = RichProgressDisplay()
        display.console = None

        display.print_info("Information")

        captured = capsys.readouterr()
        assert "Information" in captured.out

    def test_print_discovery_results_empty(self, capsys):
        """Test print_discovery_results with empty list"""
        display = RichProgressDisplay()
        display.console = None

        display.print_discovery_results([])

        captured = capsys.readouterr()
        assert "No PLCs discovered" in captured.out

    def test_print_discovery_results_with_data(self, capsys):
        """Test print_discovery_results with data"""
        display = RichProgressDisplay()
        display.console = None

        plcs = [
            {"ip_address": "192.168.1.10", "protocol": "SLMP", "manufacturer": "三菱電機"},
            {"ip_address": "192.168.1.20", "protocol": "Modbus", "manufacturer": "Unknown"},
        ]

        display.print_discovery_results(plcs)

        captured = capsys.readouterr()
        assert "192.168.1.10" in captured.out
        assert "192.168.1.20" in captured.out

    def test_print_scan_results(self, capsys):
        """Test print_scan_results"""
        display = RichProgressDisplay()
        display.console = None

        results = {
            "192.168.1.10": {
                "success": True,
                "statistics": {"total_points": 100, "success_count": 95, "error_count": 5}
            }
        }

        display.print_scan_results(results)

        captured = capsys.readouterr()
        assert "192.168.1.10" in captured.out

    def test_print_statistics(self, capsys):
        """Test print_statistics"""
        display = RichProgressDisplay()
        display.console = None

        stats = {
            "total_points": 1000,
            "success_count": 950,
            "error_count": 50,
        }

        display.print_statistics(stats)

        captured = capsys.readouterr()
        assert "1000" in captured.out or "950" in captured.out


class TestGlobalFunctions:
    """Tests for global functions"""

    def test_get_display(self):
        """Test get_display returns RichProgressDisplay"""
        display = get_display()

        assert isinstance(display, RichProgressDisplay)

    def test_get_display_singleton(self):
        """Test get_display returns same instance"""
        display1 = get_display()
        display2 = get_display()

        assert display1 is display2

    def test_is_rich_available(self):
        """Test is_rich_available returns boolean"""
        result = is_rich_available()

        assert isinstance(result, bool)

    def test_create_progress_callback(self):
        """Test creating progress callback"""
        display = RichProgressDisplay()
        task_id = 1

        callback = create_progress_callback(display, task_id)

        assert callable(callback)
