from saq.monitor import Monitor

CATEGORY_TEST = "test"
CATEGORY_DB_POOL = "db.pool"
CATEGORY_SQLALCHEMY_DB_POOL = "sqlalchemy.db.pool"

MONITOR_TEST = Monitor(
    category=CATEGORY_TEST, 
    name="test", 
    data_type=str, 
    description="Used for unit testing."
)

MONITOR_DB_POOL_AVAILABLE_COUNT = Monitor(
    category=CATEGORY_DB_POOL, 
    name="available_count", 
    data_type=int, 
    description="The current number of available database connections in the pool."
)

MONITOR_DB_POOL_IN_USE_COUNT = Monitor(
    category=CATEGORY_DB_POOL, 
    name="in_use_count", 
    data_type=int, 
    description="The current number of database connections checked out from the pool."
)

MONITOR_SQLALCHEMY_DB_POOL_STATUS = Monitor(
    category=CATEGORY_SQLALCHEMY_DB_POOL,
    name="status",
    data_type=str,
    description="The current status of the SQLAlchemy database pool."
)

CATEGORY_ERROR = "error"

MONITOR_ERROR_REPORT = Monitor(
    category=CATEGORY_ERROR,
    name="error_report",
    data_type=dict,
    description="Emitted when an unhandled exception is reported."
)