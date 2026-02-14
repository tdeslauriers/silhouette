#!/bin/bash

export  SILHOUETTE_SERVICE_CLIENT_ID=$(op read "op://world_site/silhouette_service_container_dev/client_id") 
export  SILHOUETTE_SERVICE_PORT=":$(op read "op://world_site/silhouette_service_container_dev/port")" 

export  SILHOUETTE_CA_CERT="$(op document get "service_ca_dev_cert" --vault world_site | base64 -w 0)" 
export  SILHOUETTE_SERVER_CERT="$(op document get "silhouette_service_server_dev_cert" --vault world_site | base64 -w 0)" 
export  SILHOUETTE_SERVER_KEY="$(op document get "silhouette_service_server_dev_key" --vault world_site | base64 -w 0)" 

export  SILHOUETTE_DB_CA_CERT="$(op document get "db_ca_dev_cert" --vault world_site | base64 -w 0)" 
export  SILHOUETTE_DB_CLIENT_CERT="$(op document get "silhouette_db_client_dev_cert" --vault world_site | base64 -w 0)" 
export  SILHOUETTE_DB_CLIENT_KEY="$(op document get "silhouette_db_client_dev_key" --vault world_site | base64 -w 0)" 
export  SILHOUETTE_DATABASE_URL="$(op read "op://world_site/silhouette_db_dev/server"):$(op read "op://world_site/silhouette_db_dev/port")" 
export  SILHOUETTE_DATABASE_NAME="$(op read "op://world_site/silhouette_db_dev/database")" 
export  SILHOUETTE_DATABASE_USERNAME="$(op read "op://world_site/silhouette_db_dev/username")" 
export  SILHOUETTE_DATABASE_PASSWORD="$(op read "op://world_site/silhouette_db_dev/password")" 
export  SILHOUETTE_DATABASE_HMAC_INDEX_SECRET="$(op read "op://world_site/silhouette_hmac_index_secret_dev/secret")" 
export  SILHOUETTE_FIELD_LEVEL_AES_GCM_SECRET="$(op read "op://world_site/silhouette_aes_gcm_secret_dev/secret")" 

export  SILHOUETTE_S2S_JWT_VERIFYING_KEY="$(op read "op://world_site/ran_jwt_key_pair_dev/verifying_key")" 
export  SILHOUETTE_USER_JWT_VERIFYING_KEY="$(op read "op://world_site/shaw_jwt_key_pair_dev/verifying_key")" 