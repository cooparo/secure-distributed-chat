-- migrate:up
CREATE TABLE sessions (
	id INTEGER PRIMARY KEY,
	identity_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
	root_key TEXT NOT NULL,
	our_ephemeral_key TEXT NOT NULL,
	their_ephemeral_key TEXT NOT NULL,
	send_chain_key TEXT,
	send_msg_count INTEGER,
	send_prev_msg_count INTEGER,
	recv_chain_key TEXT,
	recv_msg_count INTEGER,
	recv_prev_msg_count INTEGER
);

-- migrate:down
DROP TABLE sessions;
