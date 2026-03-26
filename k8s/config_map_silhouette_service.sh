#!/bin/bash

# Set the namespace and ConfigMap name
NAMESPACE="world"
CONFIG_MAP_NAME="cm-silhouette-service"

# get url, port, and client id from 1password
SILHOUETTE_URL=$(op read "op://world_site/silhouette_service_container_prod/url")
SILHOUETTE_PORT=$(op read "op://world_site/silhouette_service_container_prod/port")
SILHOUETTE_CLIENT_ID=$(op read "op://world_site/silhouette_service_container_prod/client_id")

# validate values are not empty
if [[ -z "$SILHOUETTE_URL" || -z "$SILHOUETTE_PORT" || -z "$SILHOUETTE_CLIENT_ID" ]]; then
  echo "Error: failed to get silhouette config vars from 1Password."
  exit 1
fi

# generate cm yaml and apply
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: $CONFIG_MAP_NAME
  namespace: $NAMESPACE
data:
  silhouette-url: "$SILHOUETTE_URL:$SILHOUETTE_PORT"
  silhouette-port: ":$SILHOUETTE_PORT"
  silhouette-client-id: "$SILHOUETTE_CLIENT_ID"
EOF
