CREATE TABLE identities (
        id INTEGER PRIMARY KEY,
        address TEXT NOT NULL UNIQUE,
        key_bundle TEXT NOT NULL,
        net_addr_bundle_time INTEGER NOT NULL,
        net_addr_bundle TEXT NOT NULL
);
