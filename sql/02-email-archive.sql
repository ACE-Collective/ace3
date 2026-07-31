-- email-archive database
-- Empty database created here; all tables are managed by alembic.
-- See alembic/email_archive.ini and alembic/email_archive/versions/.
--
-- archive, archive_index and email_history are RANGE-partitioned by insert_date;
-- the initial p_catchall partition is established by the alembic initial
-- migration, and weekly pYYYYwWW partitions are managed by
-- bin/manage-email-archive-partitions.sh.

CREATE DATABASE IF NOT EXISTS `email-archive`;
ALTER DATABASE `email-archive` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
USE `email-archive`;
