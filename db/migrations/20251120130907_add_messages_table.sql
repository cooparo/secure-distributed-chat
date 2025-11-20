-- migrate:up
CREATE TABLE messages (
	id INTEGER PRIMARY KEY,
	sender_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
	receiver_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
	timestamp INTEGER NOT NULL,
	contents TEXT NOT NULL
);

-- migrate:down
DROP TABLE messages;
