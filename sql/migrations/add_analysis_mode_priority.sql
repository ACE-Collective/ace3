CREATE TABLE IF NOT EXISTS `analysis_mode_priority` (
  `analysis_mode` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `priority` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`analysis_mode`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Priority for analysis modes. Higher values = higher priority. Modes not listed default to 0.';

INSERT IGNORE INTO `analysis_mode_priority` (`analysis_mode`, `priority`) VALUES ('correlation', 1);
