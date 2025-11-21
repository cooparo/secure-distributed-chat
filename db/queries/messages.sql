-- name: AddMessage :exec
INSERT INTO messages(
	sender_id,
	receiver_id,
	time,
	contents
)
SELECT
	(SELECT id FROM identity WHERE identity.address = sqlc.arg(sender_address)),
	(SELECT id FROM identity WHERE identity.address = sqlc.arg(receiver_address)),
	?,
	?;

-- name: GetMessages :many
SELECT
	sender.address AS sender_address,
	receiver.address AS receiver_address,
	messages.time,
	messages.contents
FROM messages
JOIN identity sender ON messages.sender_id = sender.id
JOIN identity receiver ON messages.receiver_id = receiver.id
WHERE sender.address = sqlc.arg(address)
OR receiver.address = sqlc.arg(address)
ORDER BY messages.time ASC;
