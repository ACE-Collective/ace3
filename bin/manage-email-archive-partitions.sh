#!/usr/bin/env bash
#
# Email Archive Partition Management Script
# 
# Manages weekly partitions for archive, archive_index, and email_history tables
# in the email-archive database. Partitions are named pYYYYwWW where YYYY is the year
# and WW is the week number (1-52).
#
# Actions performed:
# - Drops partitions older than 30 days
# - Creates any missing partitions 
# - Ensures next week's partition is created
#

set -euo pipefail

# Constants
DB_CONFIG_FILE="/docker-entrypoint-initdb.d/mysql_defaults.root"
DATABASE_NAME="email-archive"
RETENTION_DAYS=30
TABLES=("archive" "archive_index" "email_history")

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check if mysql client is available
command -v mysql >/dev/null 2>&1 || error_exit "mysql client not found in PATH"

# Check if config file exists
[[ -f "$DB_CONFIG_FILE" ]] || error_exit "Database config file not found: $DB_CONFIG_FILE"

# Read database connection parameters
DB_HOST=$(grep '^host=' "$DB_CONFIG_FILE" | cut -d'=' -f2)
DB_USER=$(grep '^user=' "$DB_CONFIG_FILE" | cut -d'=' -f2)
DB_PASS=$(grep '^password=' "$DB_CONFIG_FILE" | cut -d'=' -f2)

[[ -n "$DB_HOST" ]] || error_exit "Could not read database host from config"
[[ -n "$DB_USER" ]] || error_exit "Could not read database user from config"
[[ -n "$DB_PASS" ]] || error_exit "Could not read database password from config"

log "Connecting to MariaDB at $DB_HOST as $DB_USER"

# MySQL connection function
mysql_exec() {
    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -D "$DATABASE_NAME" -sN -e "$1"
}

# Function to get week number for a given date (ISO week format)
get_week_number() {
    local date_str="$1"
    date -d "$date_str" '+%V'
}

# Function to get year for a given date (ISO year format)
get_year() {
    local date_str="$1"
    date -d "$date_str" '+%G'
}

# Function to get the Monday of a given week in a given year
get_week_start_date() {
    local year="$1"
    local week="$2"
    # Get January 4th of the year (always in week 1 of ISO week-numbering year)
    local jan4=$(date -d "${year}-01-04" '+%Y-%m-%d')
    # Get the Monday of week 1
    local week1_monday=$(date -d "$jan4 -$(($(date -d "$jan4" '+%u') - 1)) days" '+%Y-%m-%d')
    # Add (week - 1) weeks to get the start of the desired week
    date -d "$week1_monday +$((week - 1)) weeks" '+%Y-%m-%d'
}

# Function to get the start date of the next week
get_next_week_start() {
    local week_start="$1"
    date -d "$week_start +1 week" '+%Y-%m-%d'
}

# Function to generate partition name
get_partition_name() {
    local year="$1"
    local week="$2"
    printf "p%04dw%02d" "$year" "$week"
}

# Function to check if a partition exists
partition_exists() {
    local table_name="$1"
    local partition_name="$2"
    
    local count=$(mysql_exec "
        SELECT COUNT(*) 
        FROM INFORMATION_SCHEMA.PARTITIONS 
        WHERE TABLE_SCHEMA = '$DATABASE_NAME' 
        AND TABLE_NAME = '$table_name' 
        AND PARTITION_NAME = '$partition_name'
    ")
    
    [[ "$count" -gt 0 ]]
}

# Function to create a partition
create_partition() {
    local table_name="$1"
    local partition_name="$2"
    local values_less_than="$3"
    
    log "Creating partition $partition_name for table $table_name (< $values_less_than)"

    if catchall_partition_exists "$table_name"; then
        log "Reorganizing catchall partition to create $partition_name"
        mysql_exec "
            ALTER TABLE $table_name REORGANIZE PARTITION p_catchall INTO (
                PARTITION $partition_name VALUES LESS THAN ('$values_less_than'),
                PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
            );
        "
    else
        mysql_exec "
            ALTER TABLE $table_name 
            ADD PARTITION (
                PARTITION $partition_name VALUES LESS THAN ('$values_less_than')
            );
        "
    fi
}

# Function to drop a partition
drop_partition() {
    local table_name="$1"
    local partition_name="$2"
    
    log "Dropping partition $partition_name from table $table_name"
    
    mysql_exec "ALTER TABLE $table_name DROP PARTITION $partition_name"
}

# Function to get all partitions for a table (excluding MAXVALUE partitions)
get_table_partitions() {
    local table_name="$1"
    
    mysql_exec "
        SELECT PARTITION_NAME 
        FROM INFORMATION_SCHEMA.PARTITIONS 
        WHERE TABLE_SCHEMA = '$DATABASE_NAME' 
        AND TABLE_NAME = '$table_name' 
        AND PARTITION_NAME IS NOT NULL
        AND PARTITION_DESCRIPTION != 'MAXVALUE'
        ORDER BY PARTITION_NAME
    "
}

# Function to check if catchall partition exists
catchall_partition_exists() {
    local table_name="$1"
    
    local count=$(mysql_exec "
        SELECT COUNT(*) 
        FROM INFORMATION_SCHEMA.PARTITIONS 
        WHERE TABLE_SCHEMA = '$DATABASE_NAME' 
        AND TABLE_NAME = '$table_name' 
        AND PARTITION_NAME = 'p_catchall'
    ")
    
    [[ "$count" -gt 0 ]]
}

# Function to get the date range of data in catchall partition
get_catchall_date_range() {
    local table_name="$1"
    
    mysql_exec "
        SELECT 
            COALESCE(MIN(DATE(insert_date)), '1970-01-01') as min_date,
            COALESCE(MAX(DATE(insert_date)), '1970-01-01') as max_date
        FROM $table_name 
        PARTITION (p_catchall)
        WHERE insert_date IS NOT NULL
    "
}

# Function to reorganize catchall partition by creating weekly partitions
reorganize_catchall_partition() {
    local table_name="$1"
    
    if ! catchall_partition_exists "$table_name"; then
        log "No catchall partition found for table $table_name, skipping reorganization"
        return 0
    fi
    
    # Get the date range of data in catchall partition
    local date_range
    date_range=$(get_catchall_date_range "$table_name")
    
    if [[ -z "$date_range" ]]; then
        log "No data found in catchall partition for table $table_name"
        return 0
    fi
    
    local min_date=$(echo "$date_range" | awk '{print $1}')
    local max_date=$(echo "$date_range" | awk '{print $2}')
    
    # Skip if no real data (default dates)
    if [[ "$min_date" == "1970-01-01" && "$max_date" == "1970-01-01" ]]; then
        log "No actual data found in catchall partition for table $table_name"
        return 0
    fi
    
    log "Found data in catchall partition for table $table_name from $min_date to $max_date"
    
    # Generate list of weekly partitions needed
    local current_date="$min_date"
    local partitions_to_create=()
    local partition_definitions=()
    
    while [[ "$(date -d "$current_date" '+%s')" -le "$(date -d "$max_date" '+%s')" ]]; do
        local current_year=$(get_year "$current_date")
        local current_week=$(get_week_number "$current_date")
        
        # Remove leading zeros
        current_week=$((10#$current_week))
        
        local partition_name=$(get_partition_name "$current_year" "$current_week")
        local week_start=$(get_week_start_date "$current_year" "$current_week")
        local next_week_start=$(get_next_week_start "$week_start")
        
        # Check if this partition already exists
        if ! partition_exists "$table_name" "$partition_name"; then
            partitions_to_create+=("$partition_name")
            partition_definitions+=("PARTITION $partition_name VALUES LESS THAN ('$next_week_start')")
            log "Will create partition $partition_name for table $table_name (< $next_week_start)"
        fi
        
        # Move to next week
        current_date=$(date -d "$current_date +1 week" '+%Y-%m-%d')
    done
    
    # If we have partitions to create, reorganize the catchall partition
    if [[ ${#partitions_to_create[@]} -gt 0 ]]; then
        log "Reorganizing catchall partition for table $table_name with ${#partitions_to_create[@]} new partitions"
        
        # Build the reorganize statement
        local reorganize_sql="ALTER TABLE $table_name REORGANIZE PARTITION p_catchall INTO ("
        
        # Add all the new partition definitions
        for i in "${!partition_definitions[@]}"; do
            if [[ $i -gt 0 ]]; then
                reorganize_sql+=", "
            fi
            reorganize_sql+="${partition_definitions[$i]}"
        done
        
        # Add the new catchall partition at the end
        reorganize_sql+=", PARTITION p_catchall VALUES LESS THAN (MAXVALUE))"
        
        log "Executing reorganize command for table $table_name"
        mysql_exec "$reorganize_sql"
        
        log "Successfully reorganized catchall partition for table $table_name"
    else
        log "No new partitions needed for catchall data in table $table_name"
    fi
}

# Function to parse partition name and get the date range
parse_partition_name() {
    local partition_name="$1"
    
    if [[ "$partition_name" =~ ^p([0-9]{4})w([0-9]{2})$ ]]; then
        local year="${BASH_REMATCH[1]}"
        local week="${BASH_REMATCH[2]}"
        echo "$year $week"
    else
        echo ""
    fi
}

# Function to check if a partition is older than retention period
is_partition_old() {
    local partition_name="$1"
    local retention_days="$2"
    
    local parsed=$(parse_partition_name "$partition_name")
    if [[ -z "$parsed" ]]; then
        return 1
    fi
    
    local year=$(echo "$parsed" | cut -d' ' -f1)
    local week=$(echo "$parsed" | cut -d' ' -f2)
    
    # Remove leading zeros
    week=$((10#$week))
    
    local week_start=$(get_week_start_date "$year" "$week")
    local cutoff_date=$(date -d "$retention_days days ago" '+%Y-%m-%d')
    
    [[ "$week_start" < "$cutoff_date" ]]
}

# Main partition management logic
manage_partitions() {
    local table_name="$1"
    
    log "Managing partitions for table: $table_name"
    
    # Get current partitions
    local partitions
    partitions=$(get_table_partitions "$table_name")
    
    # Drop old partitions
    if [[ -n "$partitions" ]]; then
        while IFS= read -r partition; do
            if is_partition_old "$partition" "$RETENTION_DAYS"; then
                drop_partition "$table_name" "$partition"
            fi
        done <<< "$partitions"
    fi
    
    # Calculate date ranges for partition creation
    local current_date=$(date '+%Y-%m-%d')
    local current_year=$(get_year "$current_date")
    local current_week=$(get_week_number "$current_date")
    
    # Remove leading zeros for arithmetic
    current_week=$((10#$current_week))
    
    # Create partitions for current week, next week, and any missing weeks
    # We'll create partitions from 4 weeks ago to 4 weeks ahead to ensure coverage
    for week_offset in {-4..4}; do
        local target_date=$(date -d "$current_date +$((week_offset * 7)) days" '+%Y-%m-%d')
        local target_year=$(get_year "$target_date")
        local target_week=$(get_week_number "$target_date")
        
        # Remove leading zeros
        target_week=$((10#$target_week))
        
        local partition_name=$(get_partition_name "$target_year" "$target_week")
        
        if ! partition_exists "$table_name" "$partition_name"; then
            local week_start=$(get_week_start_date "$target_year" "$target_week")
            local next_week_start=$(get_next_week_start "$week_start")
            
            create_partition "$table_name" "$partition_name" "$next_week_start"
        fi
    done
}

# Function to ensure table is partitioned
ensure_table_partitioned() {
    local table_name="$1"
    
    # Check if table is already partitioned
    local partition_count=$(mysql_exec "
        SELECT COUNT(*) 
        FROM INFORMATION_SCHEMA.PARTITIONS 
        WHERE TABLE_SCHEMA = '$DATABASE_NAME' 
        AND TABLE_NAME = '$table_name' 
        AND PARTITION_NAME IS NOT NULL
    ")
    
    if [[ "$partition_count" -eq 0 ]]; then
        log "Table $table_name is not partitioned. Setting up initial partitioning..."
        
        # Create initial partitioning with just a catchall partition
        # The reorganize_catchall_partition function will handle creating weekly partitions
        mysql_exec "
            ALTER TABLE $table_name 
            PARTITION BY RANGE COLUMNS(insert_date) (
                PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
            )
        "
        
        log "Initial partitioning with catchall created for table $table_name"
    elif [[ "$partition_count" -eq 1 ]] && catchall_partition_exists "$table_name"; then
        log "Table $table_name has only catchall partition, will reorganize if needed"
    fi
}

# Main execution
main() {
    log "Starting email archive partition management"
    
    # Test database connection
    mysql_exec "SELECT 1" >/dev/null || error_exit "Failed to connect to database"
    
    for table in "${TABLES[@]}"; do
        # Check if table exists
        local table_exists=$(mysql_exec "
            SELECT COUNT(*) 
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_SCHEMA = '$DATABASE_NAME' 
            AND TABLE_NAME = '$table'
        ")
        
        if [[ "$table_exists" -eq 0 ]]; then
            log "WARNING: Table $table does not exist, skipping"
            continue
        fi
        
        ensure_table_partitioned "$table"
        reorganize_catchall_partition "$table"
        manage_partitions "$table"
    done
    
    log "Email archive partition management completed successfully"
}

# Run main function
main "$@"