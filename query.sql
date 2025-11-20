-- name: AddIdentity :exec
INSERT INTO identity (
	address, keyBundle, netAddrBundleTime, netAddrBundle
) VALUES (
	?, ?, ?, ?
);

-- name: GetIdentity :one
SELECT keyBundle, netAddrBundleTime, netAddrBundle FROM identity
WHERE address = ? LIMIT 1;

-- name: GetIdentityId :one
SELECT id FROM identity
WHERE address = ? LIMIT 1;
