-- SecAudit offline CVE database schema (v1).
-- One row per CVE; one row per (CVE, CPE-version-range) match entry; references and metadata separate.

CREATE TABLE IF NOT EXISTS cve (
    cve_id         TEXT PRIMARY KEY,           -- e.g. CVE-2017-0144
    published      TEXT NOT NULL,              -- ISO 8601
    last_modified  TEXT NOT NULL,
    cvss_v3_score  REAL,                       -- nullable
    cvss_v3_vector TEXT,
    severity       TEXT,                       -- LOW | MEDIUM | HIGH | CRITICAL
    description    TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS cve_cpe_match (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id             TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    vendor             TEXT NOT NULL,
    product            TEXT NOT NULL,
    version_start_inc  TEXT,                   -- inclusive lower bound, nullable
    version_start_exc  TEXT,                   -- exclusive lower bound, nullable
    version_end_inc    TEXT,                   -- inclusive upper bound, nullable
    version_end_exc    TEXT                    -- exclusive upper bound, nullable
);
CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product
    ON cve_cpe_match(vendor, product);

CREATE TABLE IF NOT EXISTS cve_reference (
    cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    url    TEXT NOT NULL,
    tag    TEXT                                -- e.g. Patch | Vendor Advisory | Exploit
);
CREATE INDEX IF NOT EXISTS idx_ref_cve ON cve_reference(cve_id);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- Seed a well-known meta row so UI can warn when the DB is stale.
-- Application writes the real last_sync timestamp after each update cycle.
INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1');
INSERT OR IGNORE INTO meta(key, value) VALUES ('last_sync', '');
