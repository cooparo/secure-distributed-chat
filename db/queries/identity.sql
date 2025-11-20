-- name: AddIdentity :exec
INSERT INTO identity (
	address, key_bundle, net_addr_bundle_time, net_addr_bundle
) VALUES (
	?, ?, ?, ?
);

-- name: GetIdentity :one
SELECT key_bundle, net_addr_bundle_time, net_addr_bundle FROM identity
WHERE address = ? LIMIT 1;

-- name: GetIdentityId :one
SELECT id FROM identity
WHERE address = ? LIMIT 1;
