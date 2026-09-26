#!/usr/bin/env bash
#
# Analysis Result Cache Partition Management Script
#
# Manages daily partitions for the analysis_result_cache and blob_refs tables
# in the analysis-result-cache database. Partitions are named pYYYYMMDD where
# YYYY is the year, MM the month and DD the day.
#
# Actions performed:
# - Drops partitions older than the configured retention window
# - Reorganizes the catchall partition into daily partitions for any data
#   that landed before its partition existed
# - Ensures partitions exist for today and the next several days
#
# Daily (rather than weekly) partitions let the daily cron job reclaim a day
# of expired cache data at a time. The retention window is read from the ACE
# config (analysis_cache.partition_retention_days) and MUST exceed the longest
# module cache_ttl, or a partition drop could delete rows still inside their
# TTL.
#

# pull in the ACE environment so the `ace config` lookup below works; this
# also activates the venv and cd's to SAQ_HOME
source /opt/ace/bin/initialize-environment.sh

# partition DDL runs against the shared cache database, so exactly one node does it.
# defaults to primary, like is_primary_node(), so a single-node install is unaffected
if [ "${ACE_IS_PRIMARY_NODE:-1}" != "1" ]
then
    echo "not the primary node -- skipping analysis result cache partition maintenance"
    exit 0
fi

set -euo pipefail

# Constants
DB_CONFIG_FILE="/docker-entrypoint-initdb.d/mysql_defaults.root"
SSL_CA="/opt/ace/ssl/ca-chain.cert.pem"
DATABASE_NAME="analysis-result-cache"
TABLES=("analysis_result_cache" "blob_refs")

# default retention if the config lookup fails; MUST be >= 31
DEFAULT_RETENTION_DAYS=35

# how many days of partitions to provision ahead of today (buffer for missed runs)
FUTURE_DAYS=7

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

# the MySQL server presents a self-signed (ACE CA) certificate, so the client
# must be pointed at the CA chain
[[ -f "$SSL_CA" ]] || error_exit "SSL CA file not found: $SSL_CA"

# Read the partition retention window from the ACE config. It MUST exceed the
# longest module cache_ttl (30 days) or dropping a partition could delete cache
# rows that are still inside their TTL.
RETENTION_DAYS=$(ace config -v analysis_cache.partition_retention_days 2>/dev/null | tr -dc '0-9' || true)
[[ -n "$RETENTION_DAYS" ]] || RETENTION_DAYS="$DEFAULT_RETENTION_DAYS"
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || error_exit "invalid partition_retention_days: $RETENTION_DAYS"
[[ "$RETENTION_DAYS" -ge 31 ]] || error_exit "partition_retention_days ($RETENTION_DAYS) must be >= 31 to exceed the longest module cache_ttl"

# Read database connection parameters
DB_HOST=$(grep '^host=' "$DB_CONFIG_FILE" | cut -d'=' -f2)
DB_USER=$(grep '^user=' "$DB_CONFIG_FILE" | cut -d'=' -f2)
DB_PASS=$(grep '^password=' "$DB_CONFIG_FILE" | cut -d'=' -f2)

[[ -n "$DB_HOST" ]] || error_exit "Could not read database host from config"
[[ -n "$DB_USER" ]] || error_exit "Could not read database user from config"
[[ -n "$DB_PASS" ]] || error_exit "Could not read database password from config"

log "Connecting to MySQL at $DB_HOST as $DB_USER (retention: $RETENTION_DAYS days)"

# MySQL connection function
mysql_exec() {
    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" --ssl-ca="$SSL_CA" -D "$DATABASE_NAME" -sN -e "$1"
}

# Function to generate the partition name for a given date (YYYY-MM-DD)
get_partition_name() {
    local date_str="$1"
    printf "p%s" "$(date -d "$date_str" '+%Y%m%d')"
}

# Function to get the day after a given date
get_next_day() {
    local date_str="$1"
    date -d "$date_str +1 day" '+%Y-%m-%d'
}

# Function to check if a partition exists
partition_exists() {
    local table_name="$1"
    local partition_name="$2"

    local count
    count=$(mysql_exec "
        SELECT COUNT(*)
        FROM INFORMATION_SCHEMA.PARTITIONS
        WHERE TABLE_SCHEMA = '$DATABASE_NAME'
        AND TABLE_NAME = '$table_name'
        AND PARTITION_NAME = '$partition_name'
    ")

    [[ "$count" -gt 0 ]]
}

# Function to check if the catchall partition exists
catchall_partition_exists() {
    local table_name="$1"

    local count
    count=$(mysql_exec "
        SELECT COUNT(*)
        FROM INFORMATION_SCHEMA.PARTITIONS
        WHERE TABLE_SCHEMA = '$DATABASE_NAME'
        AND TABLE_NAME = '$table_name'
        AND PARTITION_NAME = 'p_catchall'
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

# Function to get all partitions for a table (excluding the MAXVALUE catchall)
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

# Function to get the date range of data in the catchall partition
get_catchall_date_range() {
    local table_name="$1"

    mysql_exec "
        SELECT
            COALESCE(MIN(DATE(created_at)), '1970-01-01') as min_date,
            COALESCE(MAX(DATE(created_at)), '1970-01-01') as max_date
        FROM $table_name
        PARTITION (p_catchall)
        WHERE created_at IS NOT NULL
    "
}

# Function to reorganize the catchall partition by creating daily partitions
# for any data that landed in it before its partition existed
reorganize_catchall_partition() {
    local table_name="$1"

    if ! catchall_partition_exists "$table_name"; then
        log "No catchall partition found for table $table_name, skipping reorganization"
        return 0
    fi

    local date_range
    date_range=$(get_catchall_date_range "$table_name")
    if [[ -z "$date_range" ]]; then
        log "No data found in catchall partition for table $table_name"
        return 0
    fi

    local min_date max_date
    min_date=$(echo "$date_range" | awk '{print $1}')
    max_date=$(echo "$date_range" | awk '{print $2}')

    # Skip if no real data (default dates)
    if [[ "$min_date" == "1970-01-01" && "$max_date" == "1970-01-01" ]]; then
        log "No actual data found in catchall partition for table $table_name"
        return 0
    fi

    log "Found data in catchall partition for table $table_name from $min_date to $max_date"

    # Generate the list of daily partitions needed to cover the catchall data
    local current_date="$min_date"
    local partition_definitions=()

    while [[ "$(date -d "$current_date" '+%s')" -le "$(date -d "$max_date" '+%s')" ]]; do
        local partition_name
        partition_name=$(get_partition_name "$current_date")
        local next_day
        next_day=$(get_next_day "$current_date")

        if ! partition_exists "$table_name" "$partition_name"; then
            partition_definitions+=("PARTITION $partition_name VALUES LESS THAN ('$next_day')")
            log "Will create partition $partition_name for table $table_name (< $next_day)"
        fi

        current_date=$(get_next_day "$current_date")
    done

    if [[ ${#partition_definitions[@]} -gt 0 ]]; then
        log "Reorganizing catchall partition for table $table_name with ${#partition_definitions[@]} new partitions"

        local reorganize_sql="ALTER TABLE $table_name REORGANIZE PARTITION p_catchall INTO ("
        for i in "${!partition_definitions[@]}"; do
            if [[ $i -gt 0 ]]; then
                reorganize_sql+=", "
            fi
            reorganize_sql+="${partition_definitions[$i]}"
        done
        reorganize_sql+=", PARTITION p_catchall VALUES LESS THAN (MAXVALUE))"

        mysql_exec "$reorganize_sql"
        log "Successfully reorganized catchall partition for table $table_name"
    else
        log "No new partitions needed for catchall data in table $table_name"
    fi
}

# Function to extract the date (YYYY-MM-DD) from a partition name (pYYYYMMDD)
parse_partition_date() {
    local partition_name="$1"

    if [[ "$partition_name" =~ ^p([0-9]{4})([0-9]{2})([0-9]{2})$ ]]; then
        echo "${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]}"
    else
        echo ""
    fi
}

# Function to check if a partition is older than the retention period
is_partition_old() {
    local partition_name="$1"
    local retention_days="$2"

    local partition_date
    partition_date=$(parse_partition_date "$partition_name")
    if [[ -z "$partition_date" ]]; then
        return 1
    fi

    local cutoff_date
    cutoff_date=$(date -d "$retention_days days ago" '+%Y-%m-%d')

    [[ "$partition_date" < "$cutoff_date" ]]
}

# Main partition management logic
manage_partitions() {
    local table_name="$1"

    log "Managing partitions for table: $table_name"

    # Drop old partitions
    local partitions
    partitions=$(get_table_partitions "$table_name")
    if [[ -n "$partitions" ]]; then
        while IFS= read -r partition; do
            if is_partition_old "$partition" "$RETENTION_DAYS"; then
                drop_partition "$table_name" "$partition"
            fi
        done <<< "$partitions"
    fi

    # Create partitions for today and the next FUTURE_DAYS days so incoming
    # rows always land in a real partition rather than the catchall
    local current_date
    current_date=$(date '+%Y-%m-%d')
    for day_offset in $(seq 0 "$FUTURE_DAYS"); do
        local target_date
        target_date=$(date -d "$current_date +$day_offset days" '+%Y-%m-%d')
        local partition_name
        partition_name=$(get_partition_name "$target_date")

        if ! partition_exists "$table_name" "$partition_name"; then
            local next_day
            next_day=$(get_next_day "$target_date")
            create_partition "$table_name" "$partition_name" "$next_day"
        fi
    done
}

# Function to ensure a table is partitioned
ensure_table_partitioned() {
    local table_name="$1"

    local partition_count
    partition_count=$(mysql_exec "
        SELECT COUNT(*)
        FROM INFORMATION_SCHEMA.PARTITIONS
        WHERE TABLE_SCHEMA = '$DATABASE_NAME'
        AND TABLE_NAME = '$table_name'
        AND PARTITION_NAME IS NOT NULL
    ")

    if [[ "$partition_count" -eq 0 ]]; then
        log "Table $table_name is not partitioned. Setting up initial partitioning..."

        # Create initial partitioning with just a catchall partition;
        # reorganize_catchall_partition handles creating daily partitions
        mysql_exec "
            ALTER TABLE $table_name
            PARTITION BY RANGE COLUMNS(created_at) (
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
    log "Starting analysis result cache partition management"

    # Test database connection
    mysql_exec "SELECT 1" >/dev/null || error_exit "Failed to connect to database"

    for table in "${TABLES[@]}"; do
        # Check if table exists
        local table_exists
        table_exists=$(mysql_exec "
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

    log "Analysis result cache partition management completed successfully"
}

# Run main function
main "$@"
