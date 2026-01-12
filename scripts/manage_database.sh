#!/bin/bash
#
# PLC Discovery - Database Management Script
#
# Usage:
#   ./scripts/manage_database.sh <command> [database_path]
#
# Commands:
#   status    - Show database status and statistics
#   tables    - List all tables with row counts
#   backup    - Create a backup of the database
#   cleanup   - Remove old data (default: older than 30 days)
#   vacuum    - Optimize database (reclaim space)
#   export    - Export data to CSV files
#   reset     - Reset database (delete all data)
#   shell     - Open SQLite interactive shell
#
# Examples:
#   ./scripts/manage_database.sh status
#   ./scripts/manage_database.sh backup ./plc_data.db
#   ./scripts/manage_database.sh cleanup ./plc_data.db 7  # Keep 7 days
#

set -e

# Default database path
DB_PATH="${2:-./plc_data.db}"
DAYS_TO_KEEP="${3:-30}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if database exists
check_db() {
    if [ ! -f "$DB_PATH" ]; then
        echo -e "${RED}Error: Database not found at $DB_PATH${NC}"
        echo "Run ./scripts/setup_database.sh to create it."
        exit 1
    fi
}

# Show usage
usage() {
    echo "Usage: $0 <command> [database_path] [options]"
    echo ""
    echo "Commands:"
    echo "  status    - Show database status and statistics"
    echo "  tables    - List all tables with row counts"
    echo "  backup    - Create a backup of the database"
    echo "  cleanup   - Remove old data (default: 30 days)"
    echo "  vacuum    - Optimize database (reclaim space)"
    echo "  export    - Export data to CSV files"
    echo "  reset     - Reset database (delete all data)"
    echo "  shell     - Open SQLite interactive shell"
    echo ""
    echo "Examples:"
    echo "  $0 status ./plc_data.db"
    echo "  $0 cleanup ./plc_data.db 7"
    exit 1
}

# Show database status
cmd_status() {
    check_db
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Database Status${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${BLUE}File Information:${NC}"
    echo "  Path: $DB_PATH"
    echo "  Size: $(du -h "$DB_PATH" | cut -f1)"
    echo "  Modified: $(stat -f '%Sm' "$DB_PATH" 2>/dev/null || stat -c '%y' "$DB_PATH" 2>/dev/null | cut -d'.' -f1)"
    echo ""
    
    echo -e "${BLUE}Schema Version:${NC}"
    sqlite3 "$DB_PATH" "SELECT '  Version: ' || version || ', Created: ' || created_at FROM schema_info;"
    echo ""
    
    echo -e "${BLUE}Statistics:${NC}"
    sqlite3 "$DB_PATH" <<'EOF'
SELECT '  Total PLCs: ' || COUNT(*) FROM plcs;
SELECT '  Total Data Points: ' || COUNT(*) FROM data_points;
SELECT '  Total Sessions: ' || COUNT(*) FROM scan_sessions;
SELECT '  Denied Addresses: ' || COUNT(*) FROM denied_addresses;
SELECT '  Value Changes: ' || COUNT(*) FROM data_history;
EOF
    echo ""
    
    echo -e "${BLUE}Recent Sessions:${NC}"
    sqlite3 -header -column "$DB_PATH" "SELECT id, mode, status, plc_count, started_at FROM scan_sessions ORDER BY id DESC LIMIT 5;"
    echo ""
    
    echo -e "${BLUE}PLCs:${NC}"
    sqlite3 -header -column "$DB_PATH" "SELECT ip_address, protocol, manufacturer, last_seen FROM plcs ORDER BY last_seen DESC LIMIT 10;"
}

# List tables with row counts
cmd_tables() {
    check_db
    
    echo -e "${BLUE}Tables and Row Counts:${NC}"
    echo ""
    
    for table in $(sqlite3 "$DB_PATH" ".tables"); do
        count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM $table;")
        printf "  %-20s %s rows\n" "$table" "$count"
    done
}

# Create backup
cmd_backup() {
    check_db
    
    BACKUP_PATH="${DB_PATH%.db}_backup_$(date +%Y%m%d_%H%M%S).db"
    
    echo -e "${BLUE}Creating backup...${NC}"
    sqlite3 "$DB_PATH" ".backup '$BACKUP_PATH'"
    
    echo -e "${GREEN}✓ Backup created: $BACKUP_PATH${NC}"
    echo "  Size: $(du -h "$BACKUP_PATH" | cut -f1)"
}

# Cleanup old data
cmd_cleanup() {
    check_db
    
    echo -e "${BLUE}Cleaning up data older than $DAYS_TO_KEEP days...${NC}"
    echo ""
    
    # Count before cleanup
    echo -e "${YELLOW}Before cleanup:${NC}"
    sqlite3 "$DB_PATH" <<EOF
SELECT '  Data points: ' || COUNT(*) FROM data_points;
SELECT '  History records: ' || COUNT(*) FROM data_history;
SELECT '  Denied addresses: ' || COUNT(*) FROM denied_addresses;
EOF
    
    # Perform cleanup
    sqlite3 "$DB_PATH" <<EOF
-- Delete old data points (keep latest per address)
DELETE FROM data_points
WHERE datetime(timestamp) < datetime('now', '-$DAYS_TO_KEEP days')
AND id NOT IN (
    SELECT MAX(id) FROM data_points
    GROUP BY plc_ip, address
);

-- Delete old history
DELETE FROM data_history
WHERE datetime(changed_at) < datetime('now', '-$DAYS_TO_KEEP days');

-- Delete old denied addresses
DELETE FROM denied_addresses
WHERE datetime(timestamp) < datetime('now', '-$DAYS_TO_KEEP days');
EOF
    
    echo ""
    echo -e "${GREEN}After cleanup:${NC}"
    sqlite3 "$DB_PATH" <<EOF
SELECT '  Data points: ' || COUNT(*) FROM data_points;
SELECT '  History records: ' || COUNT(*) FROM data_history;
SELECT '  Denied addresses: ' || COUNT(*) FROM denied_addresses;
EOF
    
    echo ""
    echo -e "${GREEN}✓ Cleanup complete!${NC}"
}

# Vacuum database
cmd_vacuum() {
    check_db
    
    SIZE_BEFORE=$(du -b "$DB_PATH" | cut -f1)
    
    echo -e "${BLUE}Optimizing database...${NC}"
    sqlite3 "$DB_PATH" "VACUUM;"
    
    SIZE_AFTER=$(du -b "$DB_PATH" | cut -f1)
    SAVED=$((SIZE_BEFORE - SIZE_AFTER))
    
    echo -e "${GREEN}✓ Optimization complete!${NC}"
    echo "  Before: $(echo $SIZE_BEFORE | numfmt --to=iec 2>/dev/null || echo "${SIZE_BEFORE} bytes")"
    echo "  After:  $(echo $SIZE_AFTER | numfmt --to=iec 2>/dev/null || echo "${SIZE_AFTER} bytes")"
    echo "  Saved:  $(echo $SAVED | numfmt --to=iec 2>/dev/null || echo "${SAVED} bytes")"
}

# Export to CSV
cmd_export() {
    check_db
    
    EXPORT_DIR="./plc_db_export_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$EXPORT_DIR"
    
    echo -e "${BLUE}Exporting data to CSV...${NC}"
    
    # Export each table
    for table in plcs scan_sessions data_points denied_addresses data_history; do
        echo "  Exporting $table..."
        sqlite3 -header -csv "$DB_PATH" "SELECT * FROM $table;" > "$EXPORT_DIR/${table}.csv"
    done
    
    echo ""
    echo -e "${GREEN}✓ Export complete!${NC}"
    echo "  Directory: $EXPORT_DIR"
    ls -la "$EXPORT_DIR"
}

# Reset database
cmd_reset() {
    check_db
    
    echo -e "${RED}WARNING: This will delete ALL data in the database!${NC}"
    read -p "Are you sure? (type 'yes' to confirm): " -r
    
    if [ "$REPLY" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
    
    echo -e "${YELLOW}Deleting all data...${NC}"
    
    sqlite3 "$DB_PATH" <<'EOF'
DELETE FROM data_history;
DELETE FROM denied_addresses;
DELETE FROM data_points;
DELETE FROM scan_sessions;
DELETE FROM plcs;
VACUUM;
EOF
    
    echo -e "${GREEN}✓ Database reset complete!${NC}"
}

# Open SQLite shell
cmd_shell() {
    check_db
    
    echo -e "${BLUE}Opening SQLite shell...${NC}"
    echo "Type .help for help, .quit to exit"
    echo ""
    
    sqlite3 "$DB_PATH"
}

# Main
case "${1:-}" in
    status)
        cmd_status
        ;;
    tables)
        cmd_tables
        ;;
    backup)
        cmd_backup
        ;;
    cleanup)
        cmd_cleanup
        ;;
    vacuum)
        cmd_vacuum
        ;;
    export)
        cmd_export
        ;;
    reset)
        cmd_reset
        ;;
    shell)
        cmd_shell
        ;;
    *)
        usage
        ;;
esac


