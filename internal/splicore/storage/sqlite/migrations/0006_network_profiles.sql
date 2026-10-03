-- Canonical, protocol-independent route/policy/DNS aggregate. Runtime caches are not stored.
CREATE TABLE client_network_profiles (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 document TEXT NOT NULL CHECK(json_valid(document))
) STRICT;
INSERT INTO client_network_profiles VALUES(1,'{}');
