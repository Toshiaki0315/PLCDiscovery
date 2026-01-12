#!/bin/bash
#
# PLC Discovery - SQLite Database Setup Script
#
# Usage:
#   ./scripts/setup_database.sh [database_path]
#
# Examples:
#   ./scripts/setup_database.sh                    # Creates ./plc_data.db
#   ./scripts/setup_database.sh /path/to/data.db  # Creates specified path
#
# Description:
#   Creates SQLite database with all required tables and indexes
#   for the PLC Discovery tool.
#

set -e

# Default database path
DB_PATH="${1:-./plc_data.db}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  PLC Discovery - Database Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if sqlite3 is available
if ! command -v sqlite3 &> /dev/null; then
    echo -e "${RED}Error: sqlite3 command not found${NC}"
    echo "Please install SQLite3:"
    echo "  macOS:  brew install sqlite"
    echo "  Ubuntu: sudo apt-get install sqlite3"
    echo "  CentOS: sudo yum install sqlite"
    exit 1
fi

# Create directory if needed
DB_DIR=$(dirname "$DB_PATH")
if [ ! -d "$DB_DIR" ] && [ "$DB_DIR" != "." ]; then
    echo -e "${YELLOW}Creating directory: $DB_DIR${NC}"
    mkdir -p "$DB_DIR"
fi

# Check if database already exists
if [ -f "$DB_PATH" ]; then
    echo -e "${YELLOW}Warning: Database already exists at $DB_PATH${NC}"
    read -p "Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Keeping existing database.${NC}"
        exit 0
    fi
    echo -e "${YELLOW}Removing existing database...${NC}"
    rm "$DB_PATH"
fi

echo -e "${GREEN}Creating database: $DB_PATH${NC}"

# Create database with schema
sqlite3 "$DB_PATH" <<'EOF'
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
    last_seen TEXT NOT NULL,
    UNIQUE(ip_address)
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
    address TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

-- Data change history (for tracking changes)
CREATE TABLE IF NOT EXISTS data_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plc_ip TEXT NOT NULL,
    address TEXT NOT NULL,
    old_value INTEGER,
    new_value INTEGER,
    changed_at TEXT NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_data_points_plc_ip ON data_points(plc_ip);
CREATE INDEX IF NOT EXISTS idx_data_points_address ON data_points(address);
CREATE INDEX IF NOT EXISTS idx_data_points_timestamp ON data_points(timestamp);
CREATE INDEX IF NOT EXISTS idx_data_points_session ON data_points(session_id);
CREATE INDEX IF NOT EXISTS idx_denied_plc_ip ON denied_addresses(plc_ip);
CREATE INDEX IF NOT EXISTS idx_plcs_ip ON plcs(ip_address);
CREATE INDEX IF NOT EXISTS idx_history_plc_ip ON data_history(plc_ip);
CREATE INDEX IF NOT EXISTS idx_history_address ON data_history(address);
CREATE INDEX IF NOT EXISTS idx_history_changed_at ON data_history(changed_at);

-- Insert schema version
INSERT INTO schema_info (version, created_at) VALUES (1, datetime('now'));

-- Verify tables
.tables
EOF

echo ""
echo -e "${GREEN}✓ Database created successfully!${NC}"
echo ""

# Show database info
echo -e "${BLUE}Database Information:${NC}"
echo "  Path: $DB_PATH"
echo "  Size: $(du -h "$DB_PATH" | cut -f1)"
echo ""

echo -e "${BLUE}Tables created:${NC}"
sqlite3 "$DB_PATH" ".tables" | sed 's/^/  /'
echo ""

echo -e "${BLUE}Schema version:${NC}"
sqlite3 "$DB_PATH" "SELECT 'Version: ' || version || ', Created: ' || created_at FROM schema_info;" | sed 's/^/  /'
echo ""

echo -e "${GREEN}Database setup complete!${NC}"
echo ""
echo -e "${BLUE}Usage examples:${NC}"
echo "  # Enable database in scanner"
echo "  python plc_scanner.py --mode full --target 192.168.1.10 --database $DB_PATH"
echo ""
echo "  # Query data"
echo "  sqlite3 $DB_PATH 'SELECT * FROM plcs;'"
echo "  sqlite3 $DB_PATH 'SELECT * FROM data_points LIMIT 10;'"


