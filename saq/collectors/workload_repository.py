import logging
from typing import Optional, List, Tuple
from saq.database import execute_with_retry, get_db_connection


class WorkloadRepository:
    """Repository class responsible for all workload-related database operations.

    Workload rows reference roots stored under the local node's collection incoming_dir,
    so every query that reads or deletes them is scoped to the node that created them.
    """

    def __init__(self, node_id: int):
        assert isinstance(node_id, int)
        self.node_id = node_id

    def get_workload_type_id(self, workload_type: str) -> int:
        """Get the workload type_id from the database, or add it if it does not already exist."""
        try:
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute("SELECT id FROM incoming_workload_type WHERE name = %s", (workload_type,))
                row = cursor.fetchone()
                if row is None:
                    cursor.execute("INSERT INTO incoming_workload_type ( name ) VALUES ( %s )", (workload_type,))
                    db.commit()
                    return cursor.lastrowid

                return row[0]

        except Exception as e:
            logging.error(f"unable to get workload type_id from database: {workload_type}")
            raise e
    
    def create_or_get_work_distribution_group(self, name: str) -> int:
        """Create a work distribution group or get its ID if it already exists."""
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT id FROM work_distribution_groups WHERE name = %s", (name,))
            row = cursor.fetchone()
            if row is None:
                cursor.execute("INSERT INTO work_distribution_groups ( name ) VALUES ( %s )", (name,))
                group_id = cursor.lastrowid
                db.commit()
            else:
                group_id = row[0]
            
            return group_id
    
    def insert_workload(self, workload_type_id: int, analysis_mode: str, root_uuid: str) -> int:
        """Insert a new workload item into the database and return its work_id."""
        with get_db_connection() as db:
            cursor = db.cursor()
            execute_with_retry(db, cursor, "INSERT INTO incoming_workload ( node_id, type_id, mode, work ) VALUES ( %s, %s, %s, %s )",
                    (self.node_id, workload_type_id, analysis_mode, root_uuid))

            if cursor.lastrowid is None:
                raise RuntimeError("missing lastrowid for INSERT transaction")

            db.commit()
            return cursor.lastrowid
    
    def assign_work_to_group(self, work_id: int, group_id: int) -> None:
        """Assign work to a specific distribution group."""
        with get_db_connection() as db:
            cursor = db.cursor()
            execute_with_retry(db, cursor, "INSERT INTO work_distribution ( work_id, group_id ) VALUES ( %s, %s )",
                    (work_id, group_id), commit=True)
    
    def get_completed_workloads(self, workload_type_id: int, limit: int = 100) -> List[Tuple[int, str]]:
        """Get a list of completed workload items (work_id, root_uuid) that can be cleaned up."""
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
SELECT 
    i.id, 
    i.work
FROM 
    incoming_workload i JOIN work_distribution w ON i.id = w.work_id
    JOIN incoming_workload_type t ON i.type_id = t.id
WHERE
    t.id = %s
    AND i.node_id = %s
GROUP BY 
    i.id, i.work
HAVING
    SUM(IF(w.status IN ('READY', 'LOCKED'), 1, 0)) = 0
LIMIT %s""", (workload_type_id, self.node_id, limit))

            rows = cursor.fetchall()
            db.commit()
            return rows
    
    def delete_workload(self, work_id: int) -> None:
        """Delete a workload item from the database."""
        with get_db_connection() as db:
            cursor = db.cursor()
            execute_with_retry(db, cursor, "DELETE FROM incoming_workload WHERE id = %s AND node_id = %s",
                    (work_id, self.node_id), commit=True)

    def get_workload_backlog_count(self, workload_type_id: int) -> int:
        """Returns the number of work distribution entries for the given workload
        type that still need to be delivered to a remote node."""
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
SELECT
    COUNT(*)
FROM
    incoming_workload i JOIN work_distribution w ON i.id = w.work_id
WHERE
    i.type_id = %s
    AND i.node_id = %s
    AND w.status IN ('READY', 'LOCKED')""", (workload_type_id, self.node_id))

            return cursor.fetchone()[0] 
