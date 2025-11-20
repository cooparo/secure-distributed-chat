CREATE TABLE identity (
	id INTEGER PRIMARY KEY,
	address TEXT NOT NULL UNIQUE,
	keyBundle TEXT NOT NULL,
	netAddrBundleTime INTEGER NOT NULL,
	netAddrBundle TEXT NOT NULL
);
