"""
Rich Progress Display Module

Provides enhanced progress display using the 'rich' library if available,
with fallback to simple console output.
"""

import sys
import time
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

# Try to import rich
try:
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        TaskProgressColumn, TimeRemainingColumn, TimeElapsedColumn
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    logger.debug("Rich library not available, using simple progress display")


class SimpleProgress:
    """Simple fallback progress display"""
    
    def __init__(self):
        self._current = 0
        self._total = 0
        self._message = ""
        self._last_update = 0
    
    def update(self, message: str, current: int = 0, total: int = 0):
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
            bar = "█" * filled + "░" * (bar_width - filled)
            print(f"\r[{bar}] {percent:5.1f}% {message}", end="", flush=True)
        else:
            print(f"\r{message}...", end="", flush=True)
    
    def complete(self, message: str = "Complete"):
        """Mark as complete"""
        print(f"\r{message}" + " " * 50)
    
    def error(self, message: str):
        """Display error"""
        print(f"\r✗ {message}" + " " * 30)


class RichProgressDisplay:
    """Rich progress display with detailed status"""
    
    def __init__(self, title: str = "PLC Scanner"):
        self.title = title
        self.console = Console() if RICH_AVAILABLE else None
        self._progress = None
        self._task_id = None
        self._status_table = None
    
    def print(self, message: str, style: str = ""):
        """Print message"""
        if self.console:
            self.console.print(message, style=style)
        else:
            print(message)
    
    def print_header(self):
        """Print application header"""
        if self.console:
            self.console.print(Panel(
                Text("PLC Discovery Tool", justify="center", style="bold blue"),
                subtitle="Factory PLC Auto-Detection and Data Collection",
                box=box.DOUBLE
            ))
        else:
            print("=" * 60)
            print("PLC Discovery Tool")
            print("Factory PLC Auto-Detection and Data Collection")
            print("=" * 60)
    
    def print_discovery_results(self, plcs: List[Dict[str, Any]]):
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
                    plc.get("ip_address", ""),
                    plc.get("protocol", ""),
                    plc.get("manufacturer", "Unknown"),
                    plc.get("model", "Unknown"),
                    str(plc.get("port", "")),
                )
            
            self.console.print(table)
        else:
            print(f"\nDiscovered {len(plcs)} PLCs:")
            for plc in plcs:
                print(f"  {plc.get('ip_address')}: {plc.get('protocol')} - {plc.get('manufacturer', 'Unknown')}")
    
    def print_scan_results(self, results: Dict[str, Any]):
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
                status = "✓ OK" if result.get("success") else "✗ Failed"
                status_style = "green" if result.get("success") else "red"
                
                table.add_row(
                    ip,
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
    
    def print_statistics(self, stats: Dict[str, Any]):
        """Print statistics summary"""
        if self.console:
            table = Table(title="Summary Statistics", box=box.SIMPLE)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", justify="right", style="green")
            
            for key, value in stats.items():
                # Format key
                formatted_key = key.replace("_", " ").title()
                table.add_row(formatted_key, str(value))
            
            self.console.print(table)
        else:
            print("\nStatistics:")
            for key, value in stats.items():
                print(f"  {key}: {value}")
    
    @contextmanager
    def progress_context(self, description: str = "Processing"):
        """Context manager for progress tracking"""
        if RICH_AVAILABLE:
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
            return self._progress.add_task(description, total=total)
        return 0
    
    def update_task(self, task_id: int, advance: int = 1, description: str = None):
        """Update progress task"""
        if self._progress:
            kwargs = {"advance": advance}
            if description:
                kwargs["description"] = description
            self._progress.update(task_id, **kwargs)
    
    def print_error(self, message: str):
        """Print error message"""
        if self.console:
            self.console.print(f"[bold red]✗ Error:[/bold red] {message}")
        else:
            print(f"✗ Error: {message}")
    
    def print_warning(self, message: str):
        """Print warning message"""
        if self.console:
            self.console.print(f"[yellow]⚠ Warning:[/yellow] {message}")
        else:
            print(f"⚠ Warning: {message}")
    
    def print_success(self, message: str):
        """Print success message"""
        if self.console:
            self.console.print(f"[bold green]✓[/bold green] {message}")
        else:
            print(f"✓ {message}")
    
    def print_info(self, message: str):
        """Print info message"""
        if self.console:
            self.console.print(f"[blue]ℹ[/blue] {message}")
        else:
            print(f"ℹ {message}")


def create_progress_callback(display: RichProgressDisplay, task_id: int):
    """Create a progress callback function for use with other modules"""
    def callback(message: str, current: int, total: int):
        if display._progress and task_id:
            display._progress.update(
                task_id,
                completed=current,
                total=total,
                description=message
            )
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


