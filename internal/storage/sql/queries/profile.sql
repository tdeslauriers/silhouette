-- name: FindProfile :one
SELECT *
FROM profile
WHERE user_index = sqlc.arg("user_index");

-- name: FindProfileAddressPhoneRows :many
SELECT 
    p.uuid AS profile_uuid, 
    p.username,
    p.nick_name,
    p.dark_mode,
    p.updated_at AS profile_updated_at,
    p.created_at AS profile_created_at,
    a.uuid AS address_uuid,
    a.slug AS address_slug,
    a.address_line_1,
    a.address_line_2,
    a.city,
    a.state,
    a.zip,
    a.country AS address_country,
    a.is_current AS address_is_current,
    a.updated_at AS address_updated_at,
    a.created_at AS address_created_at,
    ph.uuid AS phone_uuid,
    ph.slug AS phone_slug,
    ph.country_code AS phone_country_code,
    ph.phone_number,
    ph.extension,
    ph.phone_type,
    ph.is_current AS phone_is_current,
    ph.updated_at AS phone_updated_at,
    ph.created_at AS phone_created_at
FROM profile p
JOIN profile_address pa ON p.uuid = pa.profile_uuid
JOIN address a ON pa.address_uuid = a.uuid
JOIN profile_phone pp ON p.uuid = pp.profile_uuid
JOIN phone ph ON pp.phone_uuid = ph.uuid
WHERE p.user_index = sqlc.arg("user_index");

-- name: SaveProfile :exec
INSERT INTO profile (
    uuid, 
    username,
    user_index,
    nick_name,
    dark_mode,
    updated_at,
    created_at
) VALUES (
    sqlc.arg("uuid"),
    sqlc.arg("username"),
    sqlc.arg("user_index"),
    sqlc.arg("nick_name"),
    sqlc.arg("dark_mode"),
    sqlc.arg("updated_at"),
    sqlc.arg("created_at")
);

-- name: UpdateProfile :exec
UPDATE profile SET
    nick_name = sqlc.arg("nick_name"),
    dark_mode = sqlc.arg("dark_mode"),
    updated_at = sqlc.arg("updated_at")
WHERE uuid = sqlc.arg("uuid");

-- name: DeleteProfile :exec
DELETE FROM profile
WHERE uuid = sqlc.arg("uuid");