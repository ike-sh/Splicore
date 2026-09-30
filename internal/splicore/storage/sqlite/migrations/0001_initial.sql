CREATE TABLE schema_migrations (
 version INTEGER PRIMARY KEY CHECK(version > 0),
 name TEXT NOT NULL,
 checksum TEXT NOT NULL,
 applied_at TEXT NOT NULL
) STRICT;
CREATE TABLE metadata (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
) STRICT;
CREATE TABLE nodes (id TEXT PRIMARY KEY, created_at TEXT NOT NULL) STRICT;
CREATE TABLE settings (
 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
 committed_revision INTEGER NOT NULL CHECK(committed_revision >= 0)
) STRICT;
INSERT INTO settings VALUES (1, 0);
INSERT INTO metadata VALUES ('product', 'Splicore');
INSERT INTO metadata VALUES ('db_schema', '1');
CREATE TABLE accounts (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('active','suspended','closed')),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 expires_at TEXT,
 metadata TEXT NOT NULL CHECK(json_valid(metadata)),
 revision INTEGER NOT NULL CHECK(revision > 0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE inbounds (
 id TEXT PRIMARY KEY,
 node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
 name TEXT NOT NULL,
 protocol TEXT NOT NULL,
 wire_version TEXT NOT NULL,
 feature_profile TEXT NOT NULL,
 engine TEXT NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 settings_schema INTEGER NOT NULL CHECK(settings_schema = 1),
 settings TEXT NOT NULL CHECK(json_valid(settings)),
 tags TEXT NOT NULL CHECK(json_valid(tags)),
 revision INTEGER NOT NULL CHECK(revision > 0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE listeners (
 id TEXT PRIMARY KEY,
 inbound_id TEXT NOT NULL REFERENCES inbounds(id) ON DELETE RESTRICT,
 transport TEXT NOT NULL CHECK(transport IN ('tcp','udp')),
 host TEXT NOT NULL,
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 UNIQUE(inbound_id,transport,host,port)
) STRICT;
CREATE TABLE display_endpoints (
 id TEXT PRIMARY KEY,
 inbound_id TEXT NOT NULL REFERENCES inbounds(id) ON DELETE RESTRICT,
 host TEXT NOT NULL,
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 priority INTEGER NOT NULL CHECK(priority >= 0)
) STRICT;
CREATE TABLE credentials (
 id TEXT PRIMARY KEY,
 account_id TEXT REFERENCES accounts(id) ON DELETE RESTRICT,
 inbound_id TEXT REFERENCES inbounds(id) ON DELETE RESTRICT,
 kind TEXT NOT NULL CHECK(kind IN ('psk','uuid','uuid_password','username_password')),
 schema_version INTEGER NOT NULL CHECK(schema_version = 1),
 ciphertext BLOB NOT NULL,
 key_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','revoked')),
 revision INTEGER NOT NULL CHECK(revision > 0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 CHECK((account_id IS NULL) != (inbound_id IS NULL))
) STRICT;
CREATE INDEX credential_owner ON credentials(account_id);
CREATE TABLE traffic_policies (
 id TEXT PRIMARY KEY,
 quota_bytes INTEGER CHECK(quota_bytes >= 0),
 upload_bps INTEGER CHECK(upload_bps >= 0),
 download_bps INTEGER CHECK(download_bps >= 0),
 reset_policy TEXT CHECK(reset_policy IS NULL OR json_valid(reset_policy)),
 max_sessions INTEGER CHECK(max_sessions >= 0),
 revision INTEGER NOT NULL CHECK(revision > 0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE bindings (
 id TEXT PRIMARY KEY,
 account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
 inbound_id TEXT NOT NULL REFERENCES inbounds(id) ON DELETE RESTRICT,
 credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 policy_override_id TEXT REFERENCES traffic_policies(id) ON DELETE RESTRICT,
 revision INTEGER NOT NULL CHECK(revision > 0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(account_id,inbound_id)
) STRICT;
CREATE INDEX binding_inbound ON bindings(inbound_id);
CREATE TABLE transactions (
 id TEXT PRIMARY KEY,
 state TEXT NOT NULL CHECK(state IN ('pending','committed','failed')),
 base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
 target_revision INTEGER NOT NULL CHECK(target_revision > base_revision),
 principal TEXT NOT NULL,
 request_id TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 failure_code TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX transaction_state ON transactions(state);
