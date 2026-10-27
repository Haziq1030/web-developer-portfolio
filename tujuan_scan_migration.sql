USE secuscan_db;

ALTER TABLE scan_logs
    ADD COLUMN IF NOT EXISTS tujuan VARCHAR(50) NOT NULL DEFAULT 'Personal' AFTER tahap_ketepatan;

ALTER TABLE file_scan_logs
    ADD COLUMN IF NOT EXISTS tujuan VARCHAR(50) NOT NULL DEFAULT 'Personal' AFTER tahap_ketepatan;

ALTER TABLE hash_scan_logs
    ADD COLUMN IF NOT EXISTS tujuan VARCHAR(50) NOT NULL DEFAULT 'Others' AFTER provider_json;

ALTER TABLE ip_scan_logs
    ADD COLUMN IF NOT EXISTS tujuan VARCHAR(50) NOT NULL DEFAULT 'Others' AFTER usage_type;

UPDATE scan_logs SET tujuan = 'Personal' WHERE tujuan IS NULL OR tujuan = '';
UPDATE file_scan_logs SET tujuan = 'Personal' WHERE tujuan IS NULL OR tujuan = '';
UPDATE scan_logs SET tujuan = 'Others' WHERE tujuan = 'Personal';
UPDATE scan_logs SET tujuan = 'Shopping' WHERE tujuan = 'Testing';
UPDATE file_scan_logs SET tujuan = 'Others' WHERE tujuan = 'Personal';
UPDATE file_scan_logs SET tujuan = 'Shopping' WHERE tujuan = 'Testing';
UPDATE hash_scan_logs SET tujuan = 'Others' WHERE tujuan IS NULL OR tujuan = '' OR tujuan = 'Personal';
UPDATE ip_scan_logs SET tujuan = 'Others' WHERE tujuan IS NULL OR tujuan = '' OR tujuan = 'Personal';

SELECT 'URL' AS scan_type, tujuan, COUNT(*) AS total FROM scan_logs GROUP BY tujuan
UNION ALL SELECT 'File', tujuan, COUNT(*) FROM file_scan_logs GROUP BY tujuan
UNION ALL SELECT 'Hash', tujuan, COUNT(*) FROM hash_scan_logs GROUP BY tujuan
UNION ALL SELECT 'IP', tujuan, COUNT(*) FROM ip_scan_logs GROUP BY tujuan;
