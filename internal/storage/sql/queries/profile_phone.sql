-- name: InsertProfilePhone :exec
INSERT INTO profile_phone (
    id, 
    profile_uuid,
    phone_uuid,
    created_at
) VALUES (
    sqlc.arg("id"),
    sqlc.arg("profile_uuid"),
    sqlc.arg("phone_uuid"),
    sqlc.arg("created_at")
);

-- name: DeleteProfilePhoneByProfileUuid :exec
DELETE FROM profile_phone
WHERE profile_uuid = sqlc.arg("profile_uuid");

-- name: DeleteProfilePhoneByPhoneUuid :exec
DELETE FROM profile_phone
WHERE phone_uuid = sqlc.arg("phone_uuid");