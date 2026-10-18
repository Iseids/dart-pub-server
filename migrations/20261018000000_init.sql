CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('read', 'publish')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS package_versions (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    pubspec_json TEXT NOT NULL,
    archive_sha256 TEXT NOT NULL,
    archive_size INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (name, version)
);
CREATE INDEX IF NOT EXISTS package_versions_name_idx ON package_versions(name);

CREATE TABLE IF NOT EXISTS upload_sessions (
    id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    publisher_hash TEXT NOT NULL REFERENCES access_tokens(token_hash),
    status TEXT NOT NULL CHECK (status IN ('initiated', 'staged', 'published')),
    expires_at TEXT NOT NULL,
    stage_filename TEXT,
    package_name TEXT,
    package_version TEXT,
    pubspec_json TEXT,
    archive_sha256 TEXT,
    archive_size INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS upload_sessions_expires_idx ON upload_sessions(expires_at);
