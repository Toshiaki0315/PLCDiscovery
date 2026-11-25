#!/usr/bin/env python3
"""
PLC Discovery - SQLite Database Setup Script (Python version)

Usage:
    python scripts/setup_database.py [database_path]

Examples:
    python scripts/setup_database.py                    # Creates ./plc_data.db
    python scripts/setup_database.py /path/to/data.db  # Creates specified path

Description:
    Creates SQLite database with all required tables and indexes
    for the PLC Discovery tool.
"""

import argparse
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Schema shared with the scanner (single source of truth)
from plc_discovery.database import CREATE_TABLES_SQL, SCHEMA_VERSION  # noqa: E402


def setup_database(db_path_text: str, force: bool = False) -> bool:
    """
    Set up the SQLite database with required schema.

    Args:
        db_path_text: Path to database file
        force: Force recreation if database exists

    Returns:
        True if successful
    """
    db_path = Path(db_path_text)

    print("=" * 50)
    print("  PLC Discovery - Database Setup")
    print("=" * 50)
    print()

    # Create directory if needed
    if db_path.parent and not db_path.parent.exists():
        print(f"Creating directory: {db_path.parent}")
        db_path.parent.mkdir(parents=True, exist_ok=True)

    # Check if database exists
    if db_path.exists():
        if not force:
            print(f"Warning: Database already exists at {db_path}")
            response = input("Do you want to recreate it? (y/N): ").strip().lower()
            if response != "y":
                print("Keeping existing database.")
                return True

        print("Removing existing database...")
        db_path.unlink()
        # Leftover journal / WAL files belong to the removed database
        for suffix in ("-journal", "-wal", "-shm"):
            leftover = db_path.with_name(db_path.name + suffix)
            if leftover.exists():
                leftover.unlink()

    print(f"Creating database: {db_path}")

    try:
        # Create database
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Create tables
        cursor.executescript(CREATE_TABLES_SQL)

        # Insert schema version
        cursor.execute(
            "INSERT INTO schema_info (version, created_at) VALUES (?, ?)", (SCHEMA_VERSION, datetime.now().isoformat())
        )

        conn.commit()

        # Get table list
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]

        # Get schema version
        cursor.execute("SELECT version, created_at FROM schema_info ORDER BY version DESC LIMIT 1")
        version, created_at = cursor.fetchone()

        conn.close()

        print()
        print("OK: Database created successfully!")
        print()
        print("Database Information:")
        print(f"  Path: {db_path}")
        print(f"  Size: {db_path.stat().st_size / 1024:.1f} KB")
        print()
        print("Tables created:")
        for table in tables:
            print(f"  - {table}")
        print()
        print(f"Schema version: {version} (created: {created_at})")
        print()
        print("Usage examples:")
        print(f"  python plc_scanner.py --mode full --target 192.168.1.10 --database {db_path}")
        print()

        return True

    except Exception as e:
        print(f"Error: {e}")
        return False


def show_status(db_path_text: str) -> None:
    """Show database status and statistics."""
    db_path = Path(db_path_text)

    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        return

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    print("=" * 50)
    print("  Database Status")
    print("=" * 50)
    print()

    print("File Information:")
    print(f"  Path: {db_path}")
    print(f"  Size: {db_path.stat().st_size / 1024:.1f} KB")
    print()

    # Schema version
    cursor.execute("SELECT version, created_at FROM schema_info ORDER BY version DESC LIMIT 1")
    row = cursor.fetchone()
    if row:
        print(f"Schema Version: {row[0]} (created: {row[1]})")
    print()

    # Statistics
    print("Statistics:")
    tables = ["plcs", "data_points", "scan_sessions", "denied_addresses", "data_history"]
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  {table}: {count:,} rows")

    print()

    # Recent PLCs
    cursor.execute("""
        SELECT ip_address, protocol, manufacturer, last_seen
        FROM plcs ORDER BY last_seen DESC LIMIT 5
    """)
    rows = cursor.fetchall()
    if rows:
        print("Recent PLCs:")
        for row in rows:
            print(f"  {row[0]} | {row[1]} | {row[2]} | {row[3]}")

    conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="PLC Discovery - SQLite Database Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_database.py                      # Create default database
  python setup_database.py /path/to/data.db   # Create at specified path
  python setup_database.py --force             # Force recreation
  python setup_database.py --status            # Show database status
        """,
    )

    parser.add_argument(
        "database", nargs="?", default="./plc_data.db", help="Database file path (default: ./plc_data.db)"
    )

    parser.add_argument("--force", "-f", action="store_true", help="Force recreation of database")

    parser.add_argument("--status", "-s", action="store_true", help="Show database status instead of creating")

    args = parser.parse_args()

    if args.status:
        show_status(args.database)
    else:
        success = setup_database(args.database, args.force)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
