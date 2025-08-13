/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

CREATE DATABASE IF NOT EXISTS `ace`;
ALTER DATABASE `ace` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
USE `ace`;

--
-- Table structure for table `alerts`
--

DROP TABLE IF EXISTS `alerts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `alerts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(36) CHARACTER SET ascii NOT NULL,
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `storage_dir` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `tool` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `tool_instance` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `alert_type` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `description` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci DEFAULT NULL,
  `priority` int(11) NOT NULL DEFAULT '0',
  `disposition` varchar(64) CHARACTER SET ascii NOT NULL DEFAULT 'OPEN',
  `disposition_user_id` int(11) DEFAULT NULL,
  `disposition_time` timestamp NULL DEFAULT NULL,
  `owner_id` int(11) DEFAULT NULL,
  `owner_time` timestamp NULL DEFAULT NULL,
  `archived` tinyint(1) NOT NULL DEFAULT '0',
  `removal_user_id` int(11) DEFAULT NULL,
  `removal_time` timestamp NULL DEFAULT NULL,
  `company_id` int(11) DEFAULT NULL,
  `location` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `detection_count` int(11) DEFAULT '0',
  `event_time` timestamp NULL DEFAULT NULL,
  `queue` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'default',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `insert_date` (`insert_date`),
  KEY `disposition_user_id` (`disposition_user_id`),
  KEY `owner_id` (`owner_id`),
  KEY `fk_removal_user_id` (`removal_user_id`),
  KEY `idx_company_id` (`company_id`),
  KEY `idx_disposition` (`disposition`),
  KEY `idx_alert_type` (`alert_type`),
  KEY `idx_location` (`location`(767)),
  KEY `idx_queue` (`queue`),
  CONSTRAINT `fk_company` FOREIGN KEY (`company_id`) REFERENCES `company` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `campaign`
--

DROP TABLE IF EXISTS `campaign`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `campaign` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `comments`
--

DROP TABLE IF EXISTS `comments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `comments` (
  `comment_id` int(11) NOT NULL AUTO_INCREMENT,
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `user_id` int(11) NOT NULL,
  `uuid` varchar(36) CHARACTER SET ascii NOT NULL,
  `comment` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`comment_id`),
  KEY `insert_date` (`insert_date`),
  KEY `user_id` (`user_id`),
  KEY `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `company`
--

DROP TABLE IF EXISTS `company`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `company` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `company_mapping`
--

DROP TABLE IF EXISTS `company_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `company_mapping` (
  `event_id` int(11) NOT NULL,
  `company_id` int(11) NOT NULL,
  PRIMARY KEY (`event_id`,`company_id`),
  KEY `company_mapping_ibfk_2` (`company_id`),
  CONSTRAINT `company_mapping_ibfk_1` FOREIGN KEY (`event_id`) REFERENCES `events` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `company_mapping_ibfk_2` FOREIGN KEY (`company_id`) REFERENCES `company` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `config`
--

DROP TABLE IF EXISTS `config`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `config` (
  `key` varchar(512) COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `value` text COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci COMMENT='holds generic key=value configuration settings';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `delayed_analysis`
--

DROP TABLE IF EXISTS `delayed_analysis`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `delayed_analysis` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(36) CHARACTER SET ascii NOT NULL,
  `observable_uuid` char(36) CHARACTER SET ascii NOT NULL,
  `analysis_module` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `insert_date` datetime NOT NULL,
  `delayed_until` datetime DEFAULT NULL,
  `node_id` int(11) NOT NULL,
  `storage_dir` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The location of the analysis. Relative paths are relative to SAQ_HOME.',
  PRIMARY KEY (`id`),
  KEY `idx_uuid` (`uuid`),
  KEY `idx_node` (`node_id`),
  KEY `idx_node_delayed_until` (`node_id`,`delayed_until`),
  CONSTRAINT `fk_delayed_analysis_node_id` FOREIGN KEY (`node_id`) REFERENCES `nodes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `encrypted_passwords`
--

DROP TABLE IF EXISTS `encrypted_passwords`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `encrypted_passwords` (
  `key` varchar(256) COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The name (key) of the value being stored. Can either be a single name, or a section.option key.',
  `encrypted_value` text COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'Encrypted value, base64 encoded',
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_mapping`
--

DROP TABLE IF EXISTS `event_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_mapping` (
  `event_id` int(11) NOT NULL,
  `alert_id` int(11) NOT NULL,
  PRIMARY KEY (`event_id`,`alert_id`),
  KEY `event_mapping_ibfk_2` (`alert_id`),
  CONSTRAINT `event_mapping_ibfk_1` FOREIGN KEY (`event_id`) REFERENCES `events` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `event_mapping_ibfk_2` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_status`
--

DROP TABLE IF EXISTS `event_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_status` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `value` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `value_UNIQUE` (`value` ASC));
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_remediation`
--

DROP TABLE IF EXISTS `event_remediation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_remediation` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `value` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `value_UNIQUE` (`value` ASC));
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_vector`
--

DROP TABLE IF EXISTS `event_vector`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_vector` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `value` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `value_UNIQUE` (`value` ASC));
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_risk_level`
--

DROP TABLE IF EXISTS `event_risk_level`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_risk_level` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `value` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `value_UNIQUE` (`value` ASC));
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_prevention_tool`
--

DROP TABLE IF EXISTS `event_prevention_tool`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_prevention_tool` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `value` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `value_UNIQUE` (`value` ASC));
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_type`
--

DROP TABLE IF EXISTS `event_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_type` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `value` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `value_UNIQUE` (`value` ASC));
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `events`
--

DROP TABLE IF EXISTS `events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `events` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(36) CHARACTER SET ascii NOT NULL,
  `creation_date` date NOT NULL,
  `name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `type_id` int(11) NOT NULL,
  `vector_id` int(11) NOT NULL,
  `risk_level_id` int(11) NOT NULL,
  `prevention_tool_id` int(11) NOT NULL,
  `remediation_id` int(11) NOT NULL,
  `status_id` int(11) NOT NULL,
  `comment` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci,
  `campaign_id` int(11) DEFAULT NULL,
  `event_time` datetime DEFAULT NULL,
  `alert_time` datetime DEFAULT NULL,
  `ownership_time` datetime DEFAULT NULL,
  `disposition_time` datetime DEFAULT NULL,
  `contain_time` datetime DEFAULT NULL,
  `remediation_time` datetime DEFAULT NULL,
  `owner_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  UNIQUE KEY `creation_date` (`creation_date`,`name`),
  FOREIGN KEY (campaign_id) REFERENCES campaign(id),
  FOREIGN KEY (status_id) REFERENCES event_status(id),
  FOREIGN KEY (type_id) REFERENCES event_type(id),
  FOREIGN KEY (vector_id) REFERENCES event_vector(id),
  FOREIGN KEY (risk_level_id) REFERENCES event_risk_level(id),
  FOREIGN KEY (prevention_tool_id) REFERENCES event_prevention_tool(id),
  FOREIGN KEY (remediation_id) REFERENCES event_remediation(id),
  FOREIGN KEY (owner_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `incoming_workload`
--

DROP TABLE IF EXISTS `incoming_workload`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `incoming_workload` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `type_id` int(11) NOT NULL COMMENT 'Each added work item has a work type, which collectors use to know which workload items belong to them.',
  `mode` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The analysis mode the work will be submit with. This determines what nodes are selected for receiving the work.',
  `work` varchar(36) CHARACTER SET ascii NOT NULL COMMENT 'Reference UUID of the RootAnalysis relative to the incoming work directory.',
  PRIMARY KEY (`id`),
  KEY `fk_type_id_idx` (`type_id`),
  CONSTRAINT `fk_type_id` FOREIGN KEY (`type_id`) REFERENCES `incoming_workload_type` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `incoming_workload_type`
--

DROP TABLE IF EXISTS `incoming_workload_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `incoming_workload_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The name of the work (http, email, etc…)',
  PRIMARY KEY (`id`),
  UNIQUE KEY `name_UNIQUE` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `locks`
--

DROP TABLE IF EXISTS `locks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `locks` (
  `uuid` varchar(36) CHARACTER SET ascii NOT NULL,
  `lock_uuid` varchar(36) CHARACTER SET ascii DEFAULT NULL,
  `lock_time` datetime NOT NULL,
  `lock_owner` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci DEFAULT NULL,
  PRIMARY KEY (`uuid`),
  KEY `idx_lock_time` (`lock_time`),
  KEY `idx_uuid_locko_uuid` (`uuid`,`lock_uuid`),
  KEY `idx_locks_uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `malware`
--

DROP TABLE IF EXISTS `malware`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `malware` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `malware_mapping`
--

DROP TABLE IF EXISTS `malware_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `malware_mapping` (
  `event_id` int(11) NOT NULL,
  `malware_id` int(11) NOT NULL,
  PRIMARY KEY (`event_id`,`malware_id`),
  KEY `malware_mapping_ibfk_2` (`malware_id`),
  CONSTRAINT `malware_mapping_ibfk_1` FOREIGN KEY (`event_id`) REFERENCES `events` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `malware_mapping_ibfk_2` FOREIGN KEY (`malware_id`) REFERENCES `malware` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `malware_threat_mapping`
--

DROP TABLE IF EXISTS `malware_threat_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `malware_threat_mapping` (
  `malware_id` int(11) NOT NULL,
  `type` enum('UNKNOWN','KEYLOGGER','INFOSTEALER','DOWNLOADER','BOTNET','RAT','RANSOMWARE','ROOTKIT','FRAUD','CUSTOMER_THREAT', 'WIPER', 'TRAFFIC_DIRECTION_SYSTEM') NOT NULL,
  PRIMARY KEY (`malware_id`,`type`),
  CONSTRAINT `malware_threat_mapping_ibfk_1` FOREIGN KEY (`malware_id`) REFERENCES `malware` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `message_routing`
--

DROP TABLE IF EXISTS `message_routing`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `message_routing` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `message_id` bigint(20) NOT NULL,
  `route` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The route (or system) this message is to be delivered too.',
  `destination` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The destination the message should be sent to at the given route. The value of this depends on the routing system.',
  `lock` varchar(36) CHARACTER SET ascii DEFAULT NULL COMMENT 'Locking UUID.',
  `lock_time` datetime DEFAULT NULL COMMENT 'When the lock was set for this delivery. Used to time out locks.',
  PRIMARY KEY (`id`),
  KEY `idx_message_routing_mrd` (`message_id`,`route`,`destination`),
  CONSTRAINT `fk_message_routing_message_id` FOREIGN KEY (`message_id`) REFERENCES `messages` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `messages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `messages` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `content` text NOT NULL COMMENT 'The actual content of the message to be delivered.',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `node_modes`
--

DROP TABLE IF EXISTS `node_modes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `node_modes` (
  `node_id` int(11) NOT NULL,
  `analysis_mode` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The analysis_mode that this mode will support processing.',
  PRIMARY KEY (`node_id`,`analysis_mode`),
  CONSTRAINT `fk_node_id` FOREIGN KEY (`node_id`) REFERENCES `nodes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `node_modes_excluded`
--

DROP TABLE IF EXISTS `node_modes_excluded`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `node_modes_excluded` (
  `node_id` int(11) NOT NULL,
  `analysis_mode` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The analysis_mode that this node will NOT support processing.',
  PRIMARY KEY (`node_id`,`analysis_mode`),
  CONSTRAINT `fk_nme_id` FOREIGN KEY (`node_id`) REFERENCES `nodes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `nodes`
--

DROP TABLE IF EXISTS `nodes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nodes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The value of SAQ_NODE in the [global] section of the configuration file.',
  `location` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'Also called the API_PREFIX, this is the hostname:port portion of the URL for the api for the node.',
  `company_id` int(11) NOT NULL COMMENT 'The company this node belongs to (see [global] company_id in config file)',
  `last_update` datetime NOT NULL COMMENT 'The last time this node updated it’s status.',
  `is_primary` tinyint(4) NOT NULL DEFAULT '0' COMMENT '0 - node is not the primary node\\\\n1 - node is the primary node\\\\n\\\\nThe primary node is responsible for doing some basic database cleanup procedures.',
  `any_mode` tinyint(4) NOT NULL DEFAULT '0' COMMENT 'If this is true then the node_modes table is ignored for this mode as it supports any analysis mode.',
  PRIMARY KEY (`id`),
  UNIQUE KEY `node_UNIQUE` (`name`(767)),
  KEY `fk_company_id_idx` (`company_id`),
  CONSTRAINT `fk_company_id` FOREIGN KEY (`company_id`) REFERENCES `company` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `observable_mapping`
--

DROP TABLE IF EXISTS `observable_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `observable_mapping` (
  `observable_id` int(11) NOT NULL,
  `alert_id` int(11) NOT NULL,
  PRIMARY KEY (`observable_id`,`alert_id`),
  KEY `observable_mapping_ibfk_2` (`alert_id`),
  CONSTRAINT `fk_observable_mapping_1` FOREIGN KEY (`observable_id`) REFERENCES `observables` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_observable_mapping_2` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `observable_tag_index`
--

DROP TABLE IF EXISTS `observable_tag_index`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `observable_tag_index` (
  `observable_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  `alert_id` int(11) NOT NULL,
  PRIMARY KEY (`observable_id`,`tag_id`,`alert_id`),
  KEY `fk_observable_tag_index_tag_idx` (`tag_id`),
  KEY `fk_observable_tag_index_alert_idx` (`alert_id`),
  CONSTRAINT `fk_observable_tag_index_alert` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_observable_tag_index_observable` FOREIGN KEY (`observable_id`) REFERENCES `observables` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_observable_tag_index_tag` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `observable_tag_mapping`
--

DROP TABLE IF EXISTS `observable_tag_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `observable_tag_mapping` (
  `tag_id` int(11) NOT NULL,
  `observable_id` int(11) NOT NULL,
  PRIMARY KEY (`tag_id`,`observable_id`),
  KEY `observable_tag_mapping_ibfk_2` (`observable_id`),
  CONSTRAINT `fk_observable_tag_mapping_1` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_observable_tag_mapping_2` FOREIGN KEY (`observable_id`) REFERENCES `observables` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `observables`
--

DROP TABLE IF EXISTS `observables`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `observables` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `value` blob NOT NULL,
  `sha256` varbinary(32) NOT NULL,
  `for_detection` BOOLEAN NOT NULL DEFAULT False COMMENT 'whether this observable is enabled as an indicator for detection',
  `expires_on` datetime NULL DEFAULT NULL COMMENT 'the time this observable expires as an indicator for detection',
  `fa_hits` int(11) NULL DEFAULT NULL COMMENT 'the number of frequency analysis hits',
  `enabled_by` int(11) NULL DEFAULT NULL COMMENT 'who enabled this observable for detection',
  `detection_context` TEXT NULL DEFAULT NULL COMMENT 'an explanation as to why the observable was enabled for detection',
  `batch_id` varchar(36) CHARACTER SET ascii NULL DEFAULT NULL COMMENT 'a uuid used to group together observables for frequency analysis',
  PRIMARY KEY (`id`),
  UNIQUE KEY `i_type_sha256` (`type`,`sha256`),
  KEY `i_obs_sha256` (`sha256`),
  KEY `i_obs_value` (`value`(767)),
  KEY `i_batch_id` (`batch_id`),
  CONSTRAINT `fk_observables_enabled_by` FOREIGN KEY (`enabled_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `persistence`
--

DROP TABLE IF EXISTS `persistence`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `persistence` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `source_id` int(11) NOT NULL COMMENT 'The source that generated this persistence data.',
  `permanent` int(11) NOT NULL DEFAULT '0' COMMENT 'Set to 1 if this value should never be deleted, 0 otherwise.',
  `uuid` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'A unique identifier (key) for this piece of persistence data specific to this source.',
  `value` blob COMMENT 'The value of this piece of persistence data. This is pickled python data.',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'The time this information was created.',
  `last_update` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'The last time this information was updated.',
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_p_lookup` (`source_id`,`uuid`),
  KEY `idx_p_cleanup` (`permanent`,`last_update`),
  KEY `idx_p_clear_expired_1` (`source_id`,`permanent`,`created_at`),
  KEY `idx_p_clear_expired_2` (`source_id`,`permanent`,`last_update`),
  CONSTRAINT `fk_p_source` FOREIGN KEY (`source_id`) REFERENCES `persistence_source` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `persistence_source`
--

DROP TABLE IF EXISTS `persistence_source`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `persistence_source` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The name of the persistence source. For example, the name of the ace collector.',
  PRIMARY KEY (`id`),
  KEY `idx_ps_company_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `remediation`
--

DROP TABLE IF EXISTS `remediation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `remediation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(24) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'email',
  `action` enum('remove','restore') NOT NULL DEFAULT 'remove' COMMENT 'The action that was taken, either the time was removed or it was restored.',
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'The time the action occured.',
  `update_time` timestamp NULL DEFAULT NULL COMMENT 'Time the action was last attempted',
  `user_id` int(11) NOT NULL COMMENT 'The user who performed the action.',
  `key` varchar(2048) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The key to look up the item.  In the case of emails this is the message_id and the recipient email address.',
  `restore_key` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL COMMENT 'optional location used to restore the file from',
  `result` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci COMMENT 'The result of the action.  This is free form data for the analyst to see, usually includes error codes and messages.',
  `comment` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci COMMENT 'Optional comment, additional free form data.',
  `successful` tinyint(4) DEFAULT NULL COMMENT '1 - remediation worked, 0 - remediation didn’t work',
  `lock` varchar(36) DEFAULT NULL COMMENT 'Set to a UUID when an engine processes it. Defaults to NULL to indicate nothing is working on it.',
  `lock_time` datetime DEFAULT NULL,
  `status` enum('NEW','IN_PROGRESS','COMPLETED') NOT NULL DEFAULT 'NEW' COMMENT 'The current status of the remediation.\\\\n\\\\nNEW - needs to be processed\\\\nIN_PROGRESS - entry is currently being processed\\\\nCOMPLETED - entry completed successfully',
  PRIMARY KEY (`id`),
  KEY `i_key` (`key`(767)),
  KEY `fk_user_id_idx` (`user_id`),
  CONSTRAINT `fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tag_mapping`
--

DROP TABLE IF EXISTS `tag_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tag_mapping` (
  `tag_id` int(11) NOT NULL,
  `alert_id` int(11) NOT NULL,
  PRIMARY KEY (`tag_id`,`alert_id`),
  KEY `tag_mapping_ibfk_2` (`alert_id`),
  CONSTRAINT `fk_tag_mapping_1` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_tag_mapping_2` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tags`
--

DROP TABLE IF EXISTS `tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `password_hash` varchar(256) DEFAULT NULL,
  `email` varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `omniscience` int(11) NOT NULL DEFAULT '0',
  `timezone` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci DEFAULT NULL COMMENT 'The timezone this user is in. Dates and times will appear in this timezone in the GUI.',
  `display_name` varchar(1024) DEFAULT NULL COMMENT 'The display name of the user. This may be different than the username. This is used in the GUI.',
  `queue` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'default',
  `enabled` BOOLEAN NOT NULL DEFAULT True,
  `apikey_hash` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL,
  `apikey_encrypted` BLOB NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `apikey_hash` (`apikey_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `work_distribution`
--

DROP TABLE IF EXISTS `work_distribution`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `work_distribution` (
  `group_id` int(11) NOT NULL,
  `work_id` bigint(20) NOT NULL,
  `status` enum('READY','COMPLETED','ERROR','LOCKED') NOT NULL DEFAULT 'READY' COMMENT 'The status of the submission. Defaults to READY until the work has been submitted. \\nOn a successful submission the status changes to COMPLETED.\\nIf an error is detected, the status will change to ERROR.',
  `lock_time` timestamp NULL DEFAULT NULL,
  `lock_uuid` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`group_id`,`work_id`),
  KEY `fk_work_id_idx` (`work_id`),
  KEY `fk_work_status` (`work_id`,`status`),
  CONSTRAINT `fk_group_id` FOREIGN KEY (`group_id`) REFERENCES `work_distribution_groups` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_work_id` FOREIGN KEY (`work_id`) REFERENCES `incoming_workload` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `work_distribution_groups`
--

DROP TABLE IF EXISTS `work_distribution_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `work_distribution_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The name of the group (Production, QA, etc…)',
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_name_unique` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `workload`
--

DROP TABLE IF EXISTS `workload`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `workload` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(36) CHARACTER SET ascii NOT NULL,
  `node_id` int(11) NOT NULL COMMENT 'The node that contains this work item.',
  `analysis_mode` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `insert_date` datetime DEFAULT NULL,
  `company_id` int(11) NOT NULL,
  `storage_dir` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The location of the analysis. Relative paths are relative to SAQ_HOME.',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid_UNIQUE` (`uuid`,`analysis_mode`),
  KEY `fk_company_id_idx` (`company_id`),
  KEY `idx_uuid` (`uuid`),
  KEY `idx_node` (`node_id`),
  KEY `idx_analysis_mode` (`analysis_mode`),
  CONSTRAINT `fk_workload_company_id` FOREIGN KEY (`company_id`) REFERENCES `company` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_workload_node_id` FOREIGN KEY (`node_id`) REFERENCES `nodes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='the list of alerts that need to be analyzed';
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-06-08 12:37:30

DROP TABLE IF EXISTS `observable_remediation_mapping`;
CREATE TABLE `observable_remediation_mapping` (
  `observable_id` int(11) NOT NULL,
  `remediation_id` int(11) NOT NULL,
  PRIMARY KEY (`observable_id`, `remediation_id`),
  FOREIGN KEY (`observable_id`) REFERENCES `observables` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (`remediation_id`) REFERENCES `remediation` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Table structure for table `event_tag_mapping`
--

DROP TABLE IF EXISTS `event_tag_mapping`;
CREATE TABLE `event_tag_mapping` (
  `tag_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  PRIMARY KEY (`tag_id`,`event_id`),
  KEY `event_tag_mapping_ibfk_2` (`event_id`),
  CONSTRAINT `fk_event_mapping_1` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_event_tag_mapping_2` FOREIGN KEY (`event_id`) REFERENCES `events` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- user permission tables
--

CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `auth_group_user` (
  `group_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`group_id`,`user_id`),
  KEY `i_user` (`user_id`),
  CONSTRAINT `fk_agu_group` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_agu_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `auth_permission_catalog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `major` varchar(512) CHARACTER SET ascii NOT NULL,
  `minor` varchar(512) CHARACTER SET ascii NOT NULL,
  `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_perm` (`major`,`minor`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `auth_user_permission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `major` varchar(512) CHARACTER SET ascii NOT NULL,
  `minor` varchar(512) CHARACTER SET ascii NOT NULL,
  `effect` enum('ALLOW','DENY') NOT NULL DEFAULT 'ALLOW',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_user_perm` (`user_id`,`major`,`minor`,`effect`),
  KEY `i_user_major_minor` (`user_id`,`major`,`minor`),
  KEY `i_user_effect` (`user_id`,`effect`),
  CONSTRAINT `fk_aup_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_aup_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `auth_group_permission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `major` varchar(512) CHARACTER SET ascii NOT NULL,
  `minor` varchar(512) CHARACTER SET ascii NOT NULL,
  `effect` enum('ALLOW','DENY') NOT NULL DEFAULT 'ALLOW',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_group_perm` (`group_id`,`major`,`minor`,`effect`),
  KEY `i_group_major_minor` (`group_id`,`major`,`minor`),
  KEY `i_group_effect` (`group_id`,`effect`),
  CONSTRAINT `fk_agp_group` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_agp_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;