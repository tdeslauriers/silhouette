-- name: FindAllPhones :many
SELECT * 
FROM phone;

-- name: FindPhoneBySlug :one
SELECT * 
FROM phone
WHERE slug_index = sqlc.arg("slug_index");

-- name: FindPhoneByUser :one
SELECT p.* 
FROM phone p
JOIN profile_phone pp ON p.uuid = pp.phone_uuid
JOIN profile pr ON pp.profile_uuid = pr.uuid
WHERE p.slug_index = sqlc.arg("slug_index")
AND pr.user_index = sqlc.arg("user_index");


-- name: SavePhone :exec
INSERT INTO phone (
    uuid,
    slug,
    slug_index,
    country_code,
    phone_number,
    extension,
    phone_type,
    is_current,
    updated_at,
    created_at
) VALUES (
    sqlc.arg("uuid"),
    sqlc.arg("slug"),
    sqlc.arg("slug_index"),
    sqlc.arg("country_code"),
    sqlc.arg("phone_number"),
    sqlc.arg("extension"),
    sqlc.arg("phone_type"),
    sqlc.arg("is_current"),
    sqlc.arg("updated_at"),
    sqlc.arg("created_at")
);

-- name: UpdatePhone :exec
UPDATE phone
SET 
    country_code = sqlc.arg("country_code"),
    phone_number = sqlc.arg("phone_number"),
    extension = sqlc.arg("extension"),
    phone_type = sqlc.arg("phone_type"),
    is_current = sqlc.arg("is_current"),
    updated_at = sqlc.arg("updated_at")
WHERE uuid = sqlc.arg("uuid");

-- name: DeletePhone :exec
DELETE FROM phone
WHERE uuid = sqlc.arg("uuid");