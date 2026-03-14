-- name: AddIdentity :exec
INSERT INTO identities (
	address, key_bundle, net_addr_bundle_time, net_addr_bundle
) VALUES (
	?, ?, ?, ?
);

-- name: UpdateIdentity :exec
UPDATE identities
SET net_addr_bundle_time = ?, net_addr_bundle = ?
WHERE address = ?;

-- name: DeleteIdentity :exec
DELETE FROM identities
WHERE address = ?;

-- name: GetIdentity :one
SELECT key_bundle, net_addr_bundle_time, net_addr_bundle
FROM identities
WHERE address = ?;

-- name: GetIdentityId :one
SELECT id
FROM identities
WHERE address = ?;

-- name: GetRandomIdentity :one
SELECT address, key_bundle, net_addr_bundle_time, net_addr_bundle
FROM identities
ORDER BY RANDOM() LIMIT 1;

-- name: GetRandomIdentities :many
SELECT address, key_bundle, net_addr_bundle_time, net_addr_bundle
FROM identities
ORDER BY RANDOM() LIMIT ?;

-- name: GetAllIdentities :many
SELECT address
FROM identities
ORDER BY address ASC;
