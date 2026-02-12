-- Create the threat_type reference table
CREATE TABLE IF NOT EXISTS `threat_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(256) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_threat_type_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed with human-readable threat type names
INSERT IGNORE INTO `threat_type` (`name`) VALUES
  ('unknown'), ('keylogger'), ('infostealer'), ('downloader'),
  ('botnet'), ('rat'), ('ransomware'), ('rootkit'), ('fraud'),
  ('customer threat'), ('wiper'), ('traffic direction system'),
  ('advanced persistent threat');

-- Add the new FK column
ALTER TABLE `malware_threat_mapping` ADD COLUMN `threat_type_id` int(11) NULL;

-- Populate from existing ENUM data (map UPPER_CASE enum values to lowercase names)
UPDATE `malware_threat_mapping` m
  JOIN `threat_type` t ON t.name = LOWER(REPLACE(m.type, '_', ' '))
  SET m.threat_type_id = t.id;

-- Drop existing FK on malware_id so we can restructure the PK
ALTER TABLE `malware_threat_mapping` DROP FOREIGN KEY `malware_threat_mapping_ibfk_1`;

-- Drop old PK, drop old column, add new PK
ALTER TABLE `malware_threat_mapping` DROP PRIMARY KEY;
ALTER TABLE `malware_threat_mapping` DROP COLUMN `type`;
ALTER TABLE `malware_threat_mapping` MODIFY `threat_type_id` int(11) NOT NULL;
ALTER TABLE `malware_threat_mapping` ADD PRIMARY KEY (`malware_id`, `threat_type_id`);

-- Re-add the FK on malware_id and add the new FK on threat_type_id
ALTER TABLE `malware_threat_mapping` ADD CONSTRAINT `malware_threat_mapping_ibfk_1`
  FOREIGN KEY (`malware_id`) REFERENCES `malware` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `malware_threat_mapping` ADD CONSTRAINT `fk_mttm_threat_type`
  FOREIGN KEY (`threat_type_id`) REFERENCES `threat_type` (`id`);
