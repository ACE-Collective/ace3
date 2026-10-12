-- analysis result cache database
-- Empty database created here; all tables are managed by alembic_analysis_cache.
-- See alembic_analysis_cache/versions/ and docs/DATABASE_PARTITIONS.md (`ace partitions maintain`).

CREATE DATABASE IF NOT EXISTS `analysis-result-cache`;
ALTER DATABASE `analysis-result-cache` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
USE `analysis-result-cache`;
