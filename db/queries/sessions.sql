-- name: GetSession :one
SELECT
	sessions.root_key,
	sessions.our_ephemeral_key,
	sessions.their_ephemeral_key,
	sessions.send_chain_key,
	sessions.send_msg_count,
	sessions.send_prev_msg_count,
	sessions.recv_chain_key,
	sessions.recv_msg_count,
	sessions.recv_prev_msg_count
FROM identity JOIN sessions ON identity.id = sessions.identity_id
WHERE identity.address = ? LIMIT 1;

-- name: InsertSession :exec
INSERT INTO sessions(
	identity_id,
	root_key,
	our_ephemeral_key,
	their_ephemeral_key,
	send_chain_key,
	send_msg_count,
	send_prev_msg_count,
	recv_chain_key,
	recv_msg_count,
	recv_prev_msg_count
)
SELECT id, ?, ?, ?, ?, ?, ?, ?, ?, ?
FROM identity WHERE address = ?;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE identity_id = (
	SELECT id FROM identity
	WHERE address = ?
);
