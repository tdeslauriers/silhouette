#!/bin/bash

set -euo pipefail

IMAGE_NAME="silhouette:latest"
CONTAINER_NAME="silhouette-dev"

docker build --pull --no-cache -t "${IMAGE_NAME}" .

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d --rm --name "${CONTAINER_NAME}" -p $(op read "op://world_site/silhouette_service_container_dev/port"):$(op read "op://world_site/silhouette_service_container_dev/port") \
    -e SILHOUETTE_SERVICE_CLIENT_ID=$(op read "op://world_site/silhouette_service_container_dev/client_id") \
    -e SILHOUETTE_SERVICE_PORT=":$(op read "op://world_site/silhouette_service_container_dev/port")" \
    -e SILHOUETTE_CA_CERT="$(op document get "service_ca_dev_cert" --vault world_site | base64 -w 0)" \
    -e SILHOUETTE_SERVER_CERT="$(op document get "silhouette_service_server_dev_cert" --vault world_site | base64 -w 0)" \
    -e SILHOUETTE_SERVER_KEY="$(op document get "silhouette_service_server_dev_key" --vault world_site | base64 -w 0)" \
    -e SILHOUETTE_DB_CA_CERT="$(op document get "db_ca_dev_cert" --vault world_site | base64 -w 0)" \
    -e SILHOUETTE_DB_CLIENT_CERT="$(op document get "silhouette_db_client_dev_cert" --vault world_site | base64 -w 0)" \
    -e SILHOUETTE_DB_CLIENT_KEY="$(op document get "silhouette_db_client_dev_key" --vault world_site | base64 -w 0)" \
    -e SILHOUETTE_DATABASE_URL="$(op read "op://world_site/silhouette_db_dev/server"):$(op read "op://world_site/silhouette_db_dev/port")" \
    -e SILHOUETTE_DATABASE_NAME="$(op read "op://world_site/silhouette_db_dev/database")" \
    -e SILHOUETTE_DATABASE_USERNAME="$(op read "op://world_site/silhouette_db_dev/username")" \
    -e SILHOUETTE_DATABASE_PASSWORD="$(op read "op://world_site/silhouette_db_dev/password")" \
    -e SILHOUETTE_DATABASE_HMAC_INDEX_SECRET="$(op read "op://world_site/silhouette_hmac_index_secret_dev/secret")" \
    -e SILHOUETTE_FIELD_LEVEL_AES_GCM_SECRET="$(op read "op://world_site/silhouette_aes_gcm_secret_dev/secret")" \
    -e SILHOUETTE_S2S_JWT_VERIFYING_KEY="$(op read "op://world_site/ran_jwt_key_pair_dev/verifying_key")" \
    -e SILHOUETTE_USER_JWT_VERIFYING_KEY="$(op read "op://world_site/shaw_jwt_key_pair_dev/verifying_key")" \
    "${IMAGE_NAME}"
