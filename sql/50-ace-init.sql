USE `ace`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
INSERT INTO tags ( id, name ) VALUES ( 1, 'whitelisted' );
INSERT INTO users ( id, username, password_hash, email, omniscience, timezone, display_name )
VALUES ( 1, 'ace', NULL, 'ace@localhost', 0, NULL, 'automation');
INSERT INTO users ( id, username, password_hash, email, omniscience, timezone, display_name )
VALUES ( 2, 'analyst', 'pbkdf2:sha256:150000$MeWyGorw$433cf8984d385cec417cc5081140d3ee3edba8263cd49eb979209c6fabcd56bf', 'analyst@localhost', 0, 'UTC', 'analyst');
INSERT INTO `event_status` (`value`) VALUES ('OPEN'), ('CLOSED'), ('IGNORE');
INSERT INTO `event_remediation` (`value`) VALUES ('not remediated'), ('cleaned with antivirus'), ('cleaned manually'), ('reimaged'), ('credentials reset'), ('removed from mailbox'), ('network block'), ('domain takedown'), ('NA'), ('escalated');
INSERT INTO `event_vector` (`value`) VALUES ('corporate email'), ('webmail'), ('usb'), ('website'), ('unknown'), ('business application'), ('compromised website'), ('sms'), ('vpn');
INSERT INTO `event_risk_level` (`value`) VALUES ('1'), ('2'), ('3'), ('0');
INSERT INTO `event_prevention_tool` (`value`) VALUES ('response team'), ('ips'), ('fw'), ('proxy'), ('antivirus'), ('email filter'), ('application whitelisting'), ('user'), ('edr');
INSERT INTO `event_type` (`value`) VALUES ('phish'), ('recon'), ('host compromise'), ('credential compromise'), ('web browsing'), ('pentest'), ('third party'), ('large number of customer records'), ('public media');

-- Initialize permission catalog based on configured permissions in app and aceapi
INSERT INTO `auth_permission_catalog` (`major`, `minor`, `description`) VALUES
('system', 'read', 'Read system metadata and supported types via API (ping, API version, valid companies/observables/directives).'),
('email', 'read', 'Read archived email content via API/GUI.'),
('alert', 'create', 'Create new alerts or upload alert data via API/GUI.'),
('alert', 'read', 'Read alert data, submissions, status, and files via API/GUI.'),
('alert', 'write', 'Modify alerts: resubmit, add comments, set disposition, manage tags/ownership, schedule analysis.'),
('lock', 'delete', 'Clear processing locks on alerts or resources.'),
('event', 'read', 'View events, details, and export event data.'),
('event', 'write', 'Modify events (e.g., update status, associate alerts, perform background actions).'),
('observable', 'read', 'Query observables via the API using flexible filters.'),
('observable', 'write', 'Modify observables including detection status, expiration, and metadata.'),
('user', 'read', 'Read user data via API/GUI.'),
('user', 'write', 'Modify user data via API/GUI.');

-- give the built-in users full access
INSERT INTO `auth_user_permission` (`user_id`, `major`, `minor`) VALUES (1, '*', '*');
INSERT INTO `auth_user_permission` (`user_id`, `major`, `minor`) VALUES (2, '*', '*');
COMMIT;

USE `ace-unittest`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
COMMIT;

USE `ace-unittest-2`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
COMMIT;