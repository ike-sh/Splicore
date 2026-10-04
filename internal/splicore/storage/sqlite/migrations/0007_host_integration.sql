CREATE TABLE client_host_profiles (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    document TEXT NOT NULL
);
INSERT INTO client_host_profiles VALUES(1,'{"system_proxy":{"enabled":false}}');
