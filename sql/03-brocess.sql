-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database: brocess
-- ------------------------------------------------------
-- Server version	5.7.29-0ubuntu0.18.04.1

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

CREATE DATABASE IF NOT EXISTS `brocess`;
ALTER DATABASE `brocess` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
USE `brocess`;

--
-- Table structure for table `connerr`
--

DROP TABLE IF EXISTS `connerr`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `connerr` (
  `sourceip` int(11) unsigned NOT NULL,
  `destip` int(11) unsigned NOT NULL,
  `destport` int(11) NOT NULL,
  `numconnections` int(11) DEFAULT NULL,
  `firstconnectdate` double DEFAULT NULL,
  PRIMARY KEY (`sourceip`,`destip`,`destport`),
  KEY `sourceip` (`sourceip`,`destip`),
  KEY `sourceip_2` (`sourceip`),
  KEY `destip` (`destip`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `connlog`
--

DROP TABLE IF EXISTS `connlog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `connlog` (
  `sourceip` int(11) unsigned NOT NULL,
  `destip` int(11) unsigned NOT NULL,
  `destport` int(11) NOT NULL,
  `numconnections` bigint(11) DEFAULT NULL,
  `firstconnectdate` double DEFAULT NULL,
  PRIMARY KEY (`sourceip`,`destip`,`destport`),
  KEY `sourceip` (`sourceip`,`destip`),
  KEY `sourceip_2` (`sourceip`),
  KEY `destip` (`destip`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `httplog`
--

DROP TABLE IF EXISTS `httplog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `httplog` (
  `host` varbinary(255) NOT NULL,
  `numconnections` bigint(11) DEFAULT NULL,
  `firstconnectdate` double DEFAULT NULL,
  PRIMARY KEY (`host`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `properties`
--

DROP TABLE IF EXISTS `properties`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `properties` (
  `label` varbinary(255) DEFAULT NULL,
  `value` varbinary(255) DEFAULT NULL,
  UNIQUE KEY `label` (`label`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `smtplog`
--

DROP TABLE IF EXISTS `smtplog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `smtplog` (
  `source` varbinary(255) NOT NULL,
  `destination` varbinary(255) NOT NULL,
  `numconnections` bigint(11) DEFAULT NULL,
  `firstconnectdate` double DEFAULT NULL,
  PRIMARY KEY (`source`,`destination`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `email_thread_message`
--
-- records per-message metadata used to reconstruct email conversations (threads). identifiers such as
-- message-id / thread-id have no hard length limit (RFC 5322), so they are stored full-length as TEXT
-- and indexed via fixed-width BINARY(32) SHA-256 hash columns (UNHEX(SHA2(value, 256)))
--

DROP TABLE IF EXISTS `email_thread_message`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `email_thread_message` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `insert_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `thread_id` text NOT NULL,
  `thread_id_hash` binary(32) NOT NULL,
  `message_id` text NOT NULL,
  `message_id_hash` binary(32) NOT NULL,
  `in_reply_to` text DEFAULT NULL,
  `normalized_subject` text DEFAULT NULL,
  `normalized_subject_hash` binary(32) DEFAULT NULL,
  `from_address` text DEFAULT NULL,
  `from_domain` text DEFAULT NULL,
  `direction` tinyint(4) DEFAULT NULL,
  `message_date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_thread_message` (`thread_id_hash`,`message_id_hash`),
  KEY `idx_thread_date` (`thread_id_hash`,`message_date`),
  KEY `idx_subject` (`normalized_subject_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `email_thread_domain`
--
-- participant domains seen in each thread, used as the "established in-thread domains" that a
-- newly-arriving sender domain is compared against for look-a-like detection. entry_hash keeps
-- the per-thread uniqueness key fixed-width so domain/address can stay arbitrary-length TEXT.
--
-- rows are per-MESSAGE: entry_hash covers (message_id, domain, address, role), so a participant
-- present on five messages of a thread produces five rows. this is what lets the conversation
-- timeline say which message a domain appeared on. the established-domain readers in
-- saq/modules/email/conversation.py collapse these back to one entry per (domain, address, role)
-- with the earliest firstseendate.
--
-- message_id_hash is nullable only so it could be added to live tables by hand (there is no
-- migration script for it): rows written before that carry NULL and the older three-part
-- entry_hash. because the hash input changed, legacy and per-message rows cannot collide on
-- uniq_thread_domain, and the table self-heals as new mail arrives. always write it non-NULL.
--
-- a NULL row cannot be attributed to a message, so readers must not treat "not on any message" as
-- absence while a NULL row for that domain exists. Conversation.has_unattributed_domain() is how
-- callers detect that; email_thread_message.from_domain stays authoritative either way.
--
-- deliberately NOT indexed. every read filters on thread_id_hash and merely SELECTs
-- message_id_hash to bucket participants by message; nothing looks a row up by it. an index here
-- measured 97MB on a 973k-row table - 30% of all index space, larger than idx_thread - and would
-- be pure write amplification on a table written once per participant per message.
--
-- numseen is deprecated. it counted repeat sightings back when a row was per-thread; with
-- per-message rows it stays 1. count messages with COUNT(DISTINCT message_id_hash) instead.
--

DROP TABLE IF EXISTS `email_thread_domain`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `email_thread_domain` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `thread_id` text NOT NULL,
  `thread_id_hash` binary(32) NOT NULL,
  `message_id_hash` binary(32) DEFAULT NULL,
  `domain` text NOT NULL,
  `address` text NOT NULL,
  `role` varchar(16) NOT NULL,
  `entry_hash` binary(32) NOT NULL,
  `numseen` bigint(20) DEFAULT 1,
  `firstseendate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_thread_domain` (`thread_id_hash`,`entry_hash`),
  KEY `idx_thread` (`thread_id_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-01-28 13:58:16
