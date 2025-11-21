CREATE TABLE IF NOT EXISTS "schema_migrations" (version varchar(128) primary key);
CREATE TABLE identity (
        id INTEGER PRIMARY KEY,
        address TEXT NOT NULL UNIQUE,
        key_bundle TEXT NOT NULL,
        net_addr_bundle_time INTEGER NOT NULL,
        net_addr_bundle TEXT NOT NULL
);
CREATE TABLE sessions (
	id INTEGER PRIMARY KEY,
	identity_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
	root_key TEXT NOT NULL,
	our_ephemeral_key TEXT NOT NULL,
	their_ephemeral_key TEXT NOT NULL,
	send_chain_key TEXT NOT NULL,
	send_msg_count INTEGER NOT NULL,
	send_prev_msg_count INTEGER NOT NULL,
	recv_chain_key TEXT NOT NULL,
	recv_msg_count INTEGER NOT NULL,
	recv_prev_msg_count INTEGER NOT NULL
);
CREATE TABLE messages (
	id INTEGER PRIMARY KEY,
	sender_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
	receiver_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
	timestamp INTEGER NOT NULL,
	contents TEXT NOT NULL
);
-- Dbmate schema migrations
INSERT INTO "schema_migrations" (version) VALUES
  ('20251120121130'),
  ('20251120122409'),
  ('20251120130907');
