CREATE TABLE sessions (
        id INTEGER PRIMARY KEY,
        identity_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
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
