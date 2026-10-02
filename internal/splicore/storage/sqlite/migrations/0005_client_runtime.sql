-- Generic client intent and a third credential ownership scope. Existing AAD is unchanged.
CREATE TABLE remote_nodes (
 id TEXT PRIMARY KEY,
 credential_id TEXT NOT NULL UNIQUE REFERENCES credentials(id) DEFERRABLE INITIALLY DEFERRED,
 document TEXT NOT NULL CHECK(json_valid(document))
) STRICT;
CREATE TABLE bindings_v5_backup AS SELECT * FROM bindings;
DROP TABLE bindings;
CREATE TABLE credentials_v5 (
 id TEXT PRIMARY KEY,
 account_id TEXT REFERENCES accounts(id) ON DELETE RESTRICT,
 inbound_id TEXT REFERENCES inbounds(id) ON DELETE RESTRICT,
 kind TEXT NOT NULL CHECK(kind IN ('psk','uuid','uuid_password','username_password','password','private_key')),
 schema_version INTEGER NOT NULL CHECK(schema_version=1),
 ciphertext BLOB NOT NULL,
 key_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','revoked')),
 revision INTEGER NOT NULL CHECK(revision>0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 remote_node_id TEXT REFERENCES remote_nodes(id) DEFERRABLE INITIALLY DEFERRED,
 CHECK((account_id IS NOT NULL)+(inbound_id IS NOT NULL)+(remote_node_id IS NOT NULL)=1)
) STRICT;
INSERT INTO credentials_v5 SELECT *,NULL FROM credentials;
DROP TABLE credentials;
ALTER TABLE credentials_v5 RENAME TO credentials;
CREATE INDEX credential_owner ON credentials(account_id);
CREATE INDEX credential_remote_owner ON credentials(remote_node_id);
CREATE TABLE bindings (
 id TEXT PRIMARY KEY,
 account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
 inbound_id TEXT NOT NULL REFERENCES inbounds(id) ON DELETE RESTRICT,
 credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 policy_override_id TEXT REFERENCES traffic_policies(id) ON DELETE RESTRICT,
 revision INTEGER NOT NULL CHECK(revision>0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(account_id,inbound_id)
) STRICT;
INSERT INTO bindings SELECT * FROM bindings_v5_backup;
DROP TABLE bindings_v5_backup;
CREATE INDEX binding_inbound ON bindings(inbound_id);
CREATE TRIGGER snell_single_binding BEFORE INSERT ON bindings
WHEN (SELECT protocol FROM inbounds WHERE id=NEW.inbound_id)='snell'
AND EXISTS(SELECT 1 FROM bindings WHERE inbound_id=NEW.inbound_id)
BEGIN SELECT RAISE(ABORT,'Snell profile requires one binding'); END;
CREATE TABLE client_outbounds (
 id TEXT PRIMARY KEY,
 node_id TEXT REFERENCES remote_nodes(id) ON DELETE RESTRICT,
 document TEXT NOT NULL CHECK(json_valid(document))
) STRICT;
INSERT INTO client_outbounds VALUES('direct',NULL,'{"id":"direct","name":"DIRECT","kind":"direct"}');
CREATE TABLE local_inbounds (
 id TEXT PRIMARY KEY,
 outbound_id TEXT REFERENCES client_outbounds(id) ON DELETE RESTRICT,
 document TEXT NOT NULL CHECK(json_valid(document))
) STRICT;
CREATE TABLE client_routes (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 default_outbound TEXT NOT NULL REFERENCES client_outbounds(id) ON DELETE RESTRICT
) STRICT;
INSERT INTO client_routes VALUES(1,'direct');
CREATE TABLE client_profiles (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
) STRICT;
INSERT INTO client_profiles VALUES(1,1);
