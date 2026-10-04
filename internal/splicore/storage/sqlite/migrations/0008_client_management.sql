CREATE TABLE client_management_profiles (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 document TEXT NOT NULL
);
INSERT INTO client_management_profiles VALUES(1,'{"providers":[]}');
CREATE TABLE provider_sources (
 id TEXT PRIMARY KEY,
 ciphertext BLOB NOT NULL,
 key_id TEXT NOT NULL
);
