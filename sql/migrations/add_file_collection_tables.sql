-- Migration: Add file_collection tables
-- Description: Adds tables for the file collection retry system
-- Date: 2026-01-22

--
-- Table structure for table `file_collection`
--

DROP TABLE IF EXISTS `file_collection_history`;
DROP TABLE IF EXISTS `file_collection`;

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `file_collection` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The observable type (e.g., file_location).',
  `name` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The name of the FileCollector that handles this collection.',
  `key` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The observable value (e.g., hostname@/path/to/file).',
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'The time the collection was requested.',
  `update_time` timestamp NULL DEFAULT NULL COMMENT 'Time the collection was last attempted.',
  `user_id` int(11) NULL DEFAULT NULL COMMENT 'The user who requested the collection (NULL for automated).',
  `alert_uuid` varchar(36) NOT NULL COMMENT 'The UUID of the originating alert (required - files are stored in alert directory).',
  `result` enum('DELAYED','ERROR','FAILED','SUCCESS','CANCELLED','HOST_OFFLINE','FILE_NOT_FOUND') DEFAULT NULL COMMENT 'The most recent result of the collection attempt.',
  `result_message` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci DEFAULT NULL COMMENT 'Detailed message about the collection result.',
  `lock` varchar(36) DEFAULT NULL COMMENT 'Set to a UUID when a worker processes it. NULL indicates nothing is working on it.',
  `lock_time` datetime DEFAULT NULL COMMENT 'When the lock was acquired.',
  `status` enum('NEW','IN_PROGRESS','COMPLETED') NOT NULL DEFAULT 'NEW' COMMENT 'The current status of the collection.',
  `retry_count` int(11) NOT NULL DEFAULT 0 COMMENT 'Number of collection attempts so far.',
  `max_retries` int(11) NOT NULL DEFAULT 10 COMMENT 'Maximum number of retry attempts.',
  `collected_file_path` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci DEFAULT NULL COMMENT 'Path to the collected file after successful collection.',
  `collected_file_sha256` varchar(64) DEFAULT NULL COMMENT 'SHA256 hash of the collected file.',
  PRIMARY KEY (`id`),
  KEY `fk_file_collection_user_id_idx` (`user_id`),
  KEY `idx_file_collection_alert_uuid` (`alert_uuid`),
  KEY `idx_file_collection_status` (`status`),
  KEY `idx_file_collection_name` (`name`(255)),
  KEY `idx_file_collection_insert_date` (`insert_date`),
  KEY `idx_file_collection_update_time` (`update_time`),
  KEY `idx_file_collection_type` (`type`),
  KEY `idx_file_collection_result` (`result`),
  KEY `idx_file_collection_collector_loop` (`status`, `name`(255), `insert_date` DESC),
  KEY `idx_file_collection_observable_lookup` (`name`(255), `type`, `alert_uuid`),
  CONSTRAINT `fk_file_collection_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `file_collection_history`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `file_collection_history` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `file_collection_id` int(11) NOT NULL COMMENT 'Reference to the file_collection record.',
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'The time of this attempt.',
  `result` enum('DELAYED','ERROR','FAILED','SUCCESS','CANCELLED','HOST_OFFLINE','FILE_NOT_FOUND') NOT NULL COMMENT 'The result of this collection attempt.',
  `message` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'Detailed message about this attempt.',
  `status` enum('NEW','IN_PROGRESS','COMPLETED') NOT NULL COMMENT 'The resulting status after this attempt.',
  PRIMARY KEY (`id`),
  KEY `idx_file_collection_history_collection_id` (`file_collection_id`),
  KEY `idx_file_collection_history_insert_date` (`insert_date`),
  CONSTRAINT `fk_file_collection_history_collection` FOREIGN KEY (`file_collection_id`) REFERENCES `file_collection` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;
