-- name: InsertProfileAddress :exec
INSERT INTO profile_address (
    id,
    profile_uuid,
    address_uuid,
    created_at
) VALUES (
    sqlc.arg("id"),
    sqlc.arg("profile_uuid"),
    sqlc.arg("address_uuid"),
    sqlc.arg("created_at")
);

-- name: DeleteProfileAddressByProfileUuid :exec
DELETE FROM profile_address
WHERE profile_uuid = sqlc.arg("profile_uuid");

-- name: DeleteProfileAddressByAddressUuid :exec
DELETE FROM profile_address
WHERE address_uuid = sqlc.arg("address_uuid");