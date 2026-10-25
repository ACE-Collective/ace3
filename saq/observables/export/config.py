# integrations import ObservableExportConfig from here. It is defined in saq.configuration.schema with the
# other plugin base configs: config parsing validates every observable_export_ block against it, and
# importing it from this package would run saq/observables/__init__.py, every observable type with it, in
# every process that reads its configuration
from saq.configuration.schema import ObservableExportConfig  # noqa: F401
