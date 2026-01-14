-- name: FindAllAddresses :many
SELECT *
FROM address;

-- name: FindAddressByUserIndex :one
SELECT a.*
FROM address a
JOIN profile_address pa ON a.uuid = pa.address_uuid
JOIN profile p ON pa.profile_uuid = p.uuid
WHERE p.user_index = sqlc.arg("user_index");

-- name: SaveAddress :exec
INSERT INTO address (
    uuid, 
    address_line_1, 
    address_line_2, 
    city, 
    state, 
    zip, 
    country,
    is_current,
    updated_at,
    created_at
) VALUES (
    sqlc.arg("uuid"), 
    sqlc.arg("street_address"), 
    sqlc.arg("street_address_2"), 
    sqlc.arg("city"), 
    sqlc.arg("state"), 
    sqlc.arg("zip"), 
    sqlc.arg("country")
    sqlc.arg("is_current")
    sqlc.arg("updated_at")
    sqlc.arg("created_at")
);

-- name: UpdateAddress :exec
UPDATE address
SET 
    address_line_1 = sqlc.arg("street_address"),
    address_line_2 = sqlc.arg("street_address_2"),
    city = sqlc.arg("city"),
    state = sqlc.arg("state"),
    zip = sqlc.arg("zip"),
    country = sqlc.arg("country")
    is_current = sqlc.arg("is_current")
    updated_at = sqlc.arg("updated_at")
WHERE uuid = sqlc.arg("uuid");

-- name: DeleteAddress :exec
DELETE FROM address
WHERE uuid = sqlc.arg("uuid");