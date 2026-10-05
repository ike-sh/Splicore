-- Rebuild the closed credential-kind constraint without changing historical migrations.
-- Bindings are detached and restored within this same migration transaction.
CREATE TABLE bindings_v3_backup AS SELECT * FROM bindings;
DROP TABLE bindings;
CREATE TABLE credentials_v3 (
 id TEXT PRIMARY KEY,
 account_id TEXT REFERENCES accounts(id) ON DELETE RESTRICT,
 inbound_id TEXT REFERENCES inbounds(id) ON DELETE RESTRICT,
 kind TEXT NOT NULL CHECK(kind IN ('psk','uuid','uuid_password','username_password','password')),
 schema_version INTEGER NOT NULL CHECK(schema_version = 1),
 ciphertext BLOB NOT NULL,
 key_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','revoked')),
 revision INTEGER NOT NULL CHECK(revision > 0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 CHECK((account_id IS NULL) != (inbound_id IS NULL))
) STRICT;
INSERT INTO credentials_v3 SELECT * FROM credentials;
DROP TABLE credentials;
ALTER TABLE credentials_v3 RENAME TO credentials;
CREATE INDEX credential_owner ON credentials(account_id);
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
INSERT INTO bindings SELECT * FROM bindings_v3_backup;
DROP TABLE bindings_v3_backup;
CREATE INDEX binding_inbound ON bindings(inbound_id);
CREATE TRIGGER snell_single_binding BEFORE INSERT ON bindings
WHEN (SELECT protocol FROM inbounds WHERE id=NEW.inbound_id)='snell'
AND EXISTS(SELECT 1 FROM bindings WHERE inbound_id=NEW.inbound_id)
BEGIN SELECT RAISE(ABORT,'Snell profile requires one binding'); END;
