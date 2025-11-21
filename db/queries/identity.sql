-- name: AddIdentity :exec
INSERT INTO identity (
	address, key_bundle, net_addr_bundle_time, net_addr_bundle
) VALUES (
	?, ?, ?, ?
);

-- name: UpdateIdentity :exec
UPDATE identity
SET net_addr_bundle_time = ?, net_addr_bundle = ?
WHERE address = ?;

-- name: DeleteIdentity :exec
DELETE FROM identity
WHERE address = ?;

-- name: GetIdentity :one
SELECT key_bundle, net_addr_bundle_time, net_addr_bundle FROM identity
WHERE address = ?;

-- name: GetIdentityId :one
SELECT id FROM identity
WHERE address = ?;
