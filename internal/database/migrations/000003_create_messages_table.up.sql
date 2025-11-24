CREATE TABLE messages (
        id INTEGER PRIMARY KEY,
        sender_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
        receiver_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
        time INTEGER NOT NULL,
        contents TEXT NOT NULL
);
