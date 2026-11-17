"""
Rich Progress Display Module

Provides enhanced progress display using the 'rich' library if available,
with fallback to simple console output.
"""

import logging
import re
import sys
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)

# Try to import rich
try:
    from rich import box
    from rich.console import Console
    from rich.markup import escape
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    logger.debug("Rich library not available, using simple progress display")


# Control characters except newline/tab: messages and table cells can contain
# device-reported text, whose escape sequences must not reach the terminal
_TERMINAL_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(value: Any) -> str:
    """Text safe to print on a terminal (no control characters)"""
    return _TERMINAL_UNSAFE.sub("", "" if value is None else str(value))


def _cell(value: Any) -> "Text":
    """Table cell shown literally: no Rich markup, no control characters"""
    return Text(_safe(value))


class SimpleProgress:
    """Simple fallback progress display"""

    def __init__(self):
        self._current = 0
        self._total = 0
        self._message = ""
        self._last_update = 0.0

    def update(self, message: str, current: int = 0, total: int = 0) -> None:
        """Update progress"""
        self._message = message
        self._current = current
        self._total = total

        # Rate limit updates
        now = time.time()
        if now - self._last_update < 0.1:
            return
        self._last_update = now

        if total > 0:
            percent = current / total * 100
            bar_width = 30
            filled = int(bar_width * current / total)
            full, empty = ("█", "░") if _stream_can_encode("█░") else ("#", "-")
            bar = full * filled + empty * (bar_width - filled)
            print(f"\r[{bar}] {percent:5.1f}% {message}", end="", flush=True)
        else:
            print(f"\r{message}...", end="", flush=True)

    def complete(self, message: str = "Complete") -> None:
        """Mark as complete"""
        print(f"\r{message}" + " " * 50)

    def error(self, message: str) -> None:
        """Display error"""
        marker = "✗" if _stream_can_encode("✗") else "[ERROR]"
        print(f"\r{marker} {message}" + " " * 30)


def _stream_can_encode(text: str, stream: Any = None) -> bool:
    """True if the output stream's encoding can represent text"""
    stream = stream or sys.stdout
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


# Status markers; ASCII fallbacks for consoles/files whose encoding lacks the
# symbols (e.g. CP932 when output is redirected on Japanese Windows)
_SYMBOL_MARKERS = {"ok": "✓", "info": "ℹ", "warning": "⚠", "error": "✗"}
_ASCII_MARKERS = {"ok": "[OK]", "info": "[INFO]", "warning": "[WARN]", "error": "[ERROR]"}


class RichProgressDisplay:
    """Rich progress display with detailed status"""

    def __init__(self, title: str = "PLC Scanner", use_rich: bool = True):
        """
        Args:
            title: Display title
            use_rich: False for plain text output (--no-rich), e.g. for log files
        """
        self.title = title
        self.console = Console() if (RICH_AVAILABLE and use_rich) else None
        self.markers = _SYMBOL_MARKERS if _stream_can_encode("".join(_SYMBOL_MARKERS.values())) else _ASCII_MARKERS
        self._progress: Any = None
        self._task_id = None
        self._status_table = None

    def print(self, message: str, style: str = "") -> None:
        """Print message"""
        if self.console:
            self.console.print(_safe(message), style=style, markup=False)
        else:
            print(_safe(message))

    def print_header(self):
        """Print application header"""
        if self.console:
            self.console.print(
                Panel(
                    Text("PLC Discovery Tool", justify="center", style="bold blue"),
                    subtitle="Factory PLC Auto-Detection and Data Collection",
                    box=box.DOUBLE,
                )
            )
        else:
            print("=" * 60)
            print("PLC Discovery Tool")
            print("Factory PLC Auto-Detection and Data Collection")
            print("=" * 60)

    def print_discovery_results(self, plcs: List[Dict[str, Any]]) -> None:
        """Print discovery results as table"""
        if not plcs:
            self.print("No PLCs discovered.", style="yellow")
            return

        if self.console:
            table = Table(title="Discovered PLCs", box=box.ROUNDED)
            table.add_column("IP Address", style="cyan")
            table.add_column("Protocol", style="green")
            table.add_column("Manufacturer", style="magenta")
            table.add_column("Model", style="blue")
            table.add_column("Port", justify="right")

            for plc in plcs:
                table.add_row(
                    _cell(plc.get("ip_address", "")),
                    _cell(plc.get("protocol", "")),
                    _cell(plc.get("manufacturer", "Unknown")),
                    _cell(plc.get("model", "Unknown")),
                    _cell(plc.get("port", "")),
                )

            self.console.print(table)
        else:
            print(f"\nDiscovered {len(plcs)} PLCs:")
            for plc in plcs:
                print(_safe(f"  {plc.get('ip_address')}: {plc.get('protocol')} - {plc.get('manufacturer', 'Unknown')}"))

    def print_scan_results(self, results: Dict[str, Any]) -> None:
        """Print scan results"""
        if self.console:
            table = Table(title="Scan Results", box=box.ROUNDED)
            table.add_column("PLC", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Data Points", justify="right")
            table.add_column("Success", justify="right")
            table.add_column("Errors", justify="right", style="red")
            table.add_column("Duration", justify="right")

            for ip, result in results.items():
                stats = result.get("statistics", {})
                status = f"{self.markers['ok']} OK" if result.get("success") else f"{self.markers['error']} Failed"
                status_style = "green" if result.get("success") else "red"

                table.add_row(
                    _cell(ip),
                    Text(status, style=status_style),
                    str(stats.get("total_points", 0)),
                    str(stats.get("success_count", 0)),
                    str(stats.get("error_count", 0)),
                    f"{stats.get('duration_ms', 0):.0f}ms",
                )

            self.console.print(table)
        else:
            print("\nScan Results:")
            for ip, result in results.items():
                stats = result.get("statistics", {})
                status = "OK" if result.get("success") else "Failed"
                print(f"  {ip}: {status} - {stats.get('total_points', 0)} points")

    def print_statistics(self, stats: Dict[str, Any]) -> None:
        """Print statistics summary"""
        if self.console:
            table = Table(title="Summary Statistics", box=box.SIMPLE)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", justify="right", style="green")

            for key, value in stats.items():
                # Format key
                formatted_key = key.replace("_", " ").title()
                table.add_row(_cell(formatted_key), _cell(value))

            self.console.print(table)
        else:
            print("\nStatistics:")
            for key, value in stats.items():
                print(f"  {key}: {value}")

    @contextmanager
    def progress_context(self, description: str = "Processing") -> Iterator[Any]:
        """Context manager for progress tracking"""
        if self.console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=self.console,
            ) as progress:
                self._progress = progress
                yield progress
                self._progress = None
        else:
            simple = SimpleProgress()
            yield simple

    def create_task(self, description: str, total: int = 100) -> int:
        """Create a progress task"""
        if self._progress:
            return int(self._progress.add_task(description, total=total))
        return 0

    def update_task(self, task_id: int, advance: int = 1, description: Optional[str] = None) -> None:
        """Update progress task"""
        if self._progress:
            kwargs: Dict[str, Any] = {"advance": advance}
            if description:
                kwargs["description"] = description
            self._progress.update(task_id, **kwargs)

    def _print_marked(self, kind: str, style: str, message: str, label: str = "") -> None:
        marker = self.markers[kind]
        if self.markers is _ASCII_MARKERS:
            label = ""  # "[ERROR]" already says it
        prefix = f"{marker} {label}".rstrip()
        if self.console:
            self.console.print(f"[{style}]{escape(prefix)}[/{style}] {escape(_safe(message))}")
        else:
            print(f"{prefix} {_safe(message)}")

    def print_error(self, message: str) -> None:
        """Print error message"""
        self._print_marked("error", "bold red", message, "Error:")

    def print_warning(self, message: str) -> None:
        """Print warning message"""
        self._print_marked("warning", "yellow", message, "Warning:")

    def print_success(self, message: str) -> None:
        """Print success message"""
        self._print_marked("ok", "bold green", message)

    def print_info(self, message: str) -> None:
        """Print info message"""
        self._print_marked("info", "blue", message)


def create_progress_callback(display: RichProgressDisplay, task_id: int) -> Callable[[str, int, int], None]:
    """Create a progress callback function for use with other modules"""

    def callback(message: str, current: int, total: int) -> None:
        if display._progress and task_id:
            display._progress.update(task_id, completed=current, total=total, description=message)

    return callback


# Global display instance
_display: Optional[RichProgressDisplay] = None


def get_display() -> RichProgressDisplay:
    """Get global display instance"""
    global _display
    if _display is None:
        _display = RichProgressDisplay()
    return _display


def is_rich_available() -> bool:
    """Check if rich library is available"""
    return RICH_AVAILABLE
