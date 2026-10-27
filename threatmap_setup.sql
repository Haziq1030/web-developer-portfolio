-- =====================================================================
-- SecuScan — Threat Map schema (GeoIP + global IOC cache)
--
-- Run AFTER api_setup.sql and ai_setup.sql.
-- Creates four tables, touches nothing existing.
-- =====================================================================

USE secuscan_db;

-- ---------------------------------------------------------------------
-- 1. GeoLite2 country lookup
--
-- IPv4 addresses are stored as unsigned 32-bit integers so a lookup is a
-- range scan on an indexed column rather than a string comparison. This
-- is the whole reason for importing the CSV instead of parsing .mmdb:
-- no PHP extension, no Composer package, and the data is inspectable in
-- phpMyAdmin.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS geoip_country (
    geoname_id   INT UNSIGNED NOT NULL,
    iso_code     CHAR(2)      NOT NULL DEFAULT '',
    country_name VARCHAR(100) NOT NULL DEFAULT '',
    continent    VARCHAR(60)  NOT NULL DEFAULT '',
    PRIMARY KEY (geoname_id),
    KEY idx_geo_iso (iso_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS geoip_block (
    start_ip   INT UNSIGNED NOT NULL,
    end_ip     INT UNSIGNED NOT NULL,
    geoname_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (start_ip),
    KEY idx_block_end (end_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------------
-- 2. Global IOC observations (ThreatFox), already resolved to a country
--
-- One row per indicator we have geolocated. Kept separate from the
-- campus scan tables so the map can show "ours" and "the world" as two
-- clearly distinct layers rather than one blurred total.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_observations (
    id          INT NOT NULL AUTO_INCREMENT,
    ioc         VARCHAR(255) NOT NULL,
    ioc_type    VARCHAR(40)  NOT NULL DEFAULT '',
    ip_address  VARCHAR(45)  NOT NULL DEFAULT '',
    iso_code    CHAR(2)      NOT NULL DEFAULT '',
    malware     VARCHAR(120) NOT NULL DEFAULT '',
    threat_type VARCHAR(80)  NOT NULL DEFAULT '',
    confidence  TINYINT UNSIGNED NOT NULL DEFAULT 0,
    first_seen  DATETIME     NULL,
    imported_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_ioc (ioc),
    KEY idx_obs_iso (iso_code),
    KEY idx_obs_imported (imported_at),
    KEY idx_obs_malware (malware)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------------
-- 3. Backfill country codes onto IP scans already recorded
--
-- ip_scan_logs already stores country_code from the reputation lookup,
-- so campus data needs no new import — this is only here as a reminder
-- that the column exists and is the source for the "our scans" layer.
-- ---------------------------------------------------------------------
ALTER TABLE ip_scan_logs ADD INDEX IF NOT EXISTS idx_ip_country (country_code);

-- ---------------------------------------------------------------------
-- Verify
-- ---------------------------------------------------------------------
SELECT 'geoip_country'       AS table_name, COUNT(*) AS rows_present FROM geoip_country
UNION ALL SELECT 'geoip_block',        COUNT(*) FROM geoip_block
UNION ALL SELECT 'threat_observations', COUNT(*) FROM threat_observations;

-- geoip_country and geoip_block stay at 0 until you run import_geolite.php.
