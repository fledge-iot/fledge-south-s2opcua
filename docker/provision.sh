#!/bin/sh
# Creates (or updates) the s2opcua south service in the local Fledge, pointing at the
# OPC PLC test server. Run by the "provision" service in ../docker-compose.yml.
#
# For Security Mode Sign/SignAndEncrypt or username authentication it also:
#   - copies the OPC PLC server certificate into the Fledge certificate store
#   - creates a self-signed client certificate and key for the plugin (once)
set -eu

FLEDGE_URL="${FLEDGE_URL:-http://fledge:8081}"
SERVICE_NAME="${SERVICE_NAME:-opcua}"
OPCUA_URL="${OPCUA_URL:-opc.tcp://opcplc:50000}"
OPCUA_SUBSCRIPTIONS="${OPCUA_SUBSCRIPTIONS:-ns=3;s=Basic}"
OPCUA_SECURITY_MODE="${OPCUA_SECURITY_MODE:-None}"
OPCUA_SECURITY_POLICY="${OPCUA_SECURITY_POLICY:-None}"
OPCUA_AUTH="${OPCUA_AUTH:-anonymous}"
OPCUA_USERNAME="${OPCUA_USERNAME:-}"
OPCUA_PASSWORD="${OPCUA_PASSWORD:-}"

CERT_DIR=/fledge-data/etc/certs
SERVER_CERT_NAME=opcplc
CLIENT_CERT_NAME=fledge-client
APPLICATION_URI=fledge.south.s2opcua

apk add --no-cache curl jq openssl >/dev/null

echo "Waiting for Fledge at ${FLEDGE_URL} ..."
until curl -fsS "${FLEDGE_URL}/fledge/ping" >/dev/null 2>&1; do sleep 2; done

# Log in if the Fledge API requires authentication (Fledge default admin account unless overridden)
auth_header="X-No-Auth: 1"
if [ "$(curl -fsS "${FLEDGE_URL}/fledge/ping" | jq -r '.authenticationOptional')" = "false" ]; then
    token=$(curl -fsS -X POST "${FLEDGE_URL}/fledge/login" -H 'Content-Type: application/json' \
        -d "$(jq -n -c --arg u "${FLEDGE_USER:-admin}" --arg p "${FLEDGE_PASSWORD:-fledge}" '{username: $u, password: $p}')" \
        | jq -r '.token')
    auth_header="Authorization: ${token}"
fi

server_cert=""
client_cert=""
client_key=""
if [ "${OPCUA_SECURITY_MODE}" != "None" ] || [ "${OPCUA_AUTH}" = "username" ]; then
    echo "Waiting for the OPC PLC server certificate ..."
    pki_cert=""
    while [ -z "${pki_cert}" ]; do
        pki_cert=$(find /opcplc-pki/own/certs -name '*.der' 2>/dev/null | head -n 1)
        [ -n "${pki_cert}" ] || sleep 2
    done
    mkdir -p "${CERT_DIR}/pem"
    cp "${pki_cert}" "${CERT_DIR}/${SERVER_CERT_NAME}.der"
    server_cert="${SERVER_CERT_NAME}"
    echo "Server certificate: ${pki_cert} -> ${CERT_DIR}/${SERVER_CERT_NAME}.der"

    if [ ! -f "${CERT_DIR}/${CLIENT_CERT_NAME}.der" ] || [ ! -f "${CERT_DIR}/pem/${CLIENT_CERT_NAME}.pem" ]; then
        # Requirements from docs/index.rst "Certificate Requirements"
        openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
            -keyout "${CERT_DIR}/pem/${CLIENT_CERT_NAME}.pem" \
            -out "${CERT_DIR}/${CLIENT_CERT_NAME}.der" -outform DER \
            -subj "/CN=S2OPCUA South Plugin/O=Fledge" \
            -addext "subjectAltName=URI:${APPLICATION_URI},DNS:fledge" \
            -addext "keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment" \
            -addext "extendedKeyUsage=clientAuth" \
            -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null
        echo "Created client certificate ${CERT_DIR}/${CLIENT_CERT_NAME}.der"
    fi
    client_cert="${CLIENT_CERT_NAME}"
    client_key="${CLIENT_CERT_NAME}"
fi

subscriptions=$(printf '%s' "${OPCUA_SUBSCRIPTIONS}" | jq -R -c '{subscriptions: split(",")}')

# Configuration item values, as Fledge expects them (all strings)
values=$(jq -n -c \
    --arg url "${OPCUA_URL}" \
    --arg subscription "${subscriptions}" \
    --arg securityMode "${OPCUA_SECURITY_MODE}" \
    --arg securityPolicy "${OPCUA_SECURITY_POLICY}" \
    --arg userAuthPolicy "${OPCUA_AUTH}" \
    --arg username "${OPCUA_USERNAME}" \
    --arg password "${OPCUA_PASSWORD}" \
    --arg serverCert "${server_cert}" \
    --arg clientCert "${client_cert}" \
    --arg clientKey "${client_key}" \
    '{url: $url, subscription: $subscription, securityMode: $securityMode, securityPolicy: $securityPolicy,
      userAuthPolicy: $userAuthPolicy, username: $username, password: $password,
      serverCert: $serverCert, clientCert: $clientCert, clientKey: $clientKey}')

if curl -fsS -H "${auth_header}" "${FLEDGE_URL}/fledge/category/${SERVICE_NAME}" >/dev/null 2>&1; then
    echo "Updating the configuration of south service '${SERVICE_NAME}'"
    # The plugin reconfigures itself (plugin_reconfigure) when its configuration changes
    curl -fsS -X PUT -H "${auth_header}" "${FLEDGE_URL}/fledge/category/${SERVICE_NAME}" \
        -H 'Content-Type: application/json' -d "${values}" >/dev/null
else
    echo "Creating south service '${SERVICE_NAME}'"
    payload=$(printf '%s' "${values}" | jq -c --arg name "${SERVICE_NAME}" \
        '{name: $name, type: "south", plugin: "s2opcua", enabled: true, config: with_entries(.value = {value: .value})}')
    curl -fsS -X POST -H "${auth_header}" "${FLEDGE_URL}/fledge/service" -H 'Content-Type: application/json' -d "${payload}"
    echo
fi

echo "Done: Security Mode '${OPCUA_SECURITY_MODE}', Security Policy '${OPCUA_SECURITY_POLICY}', authentication '${OPCUA_AUTH}'"
echo "Plugin logs: docker compose logs -f fledge | grep s2opcua"
echo "Readings:    http://localhost:8081/fledge/asset (log in first: POST /fledge/login, default admin/fledge)"
