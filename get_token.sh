#!/bin/bash

# ─────────────────────────────────────────────────────────────────────────────
# get_token.sh — Acquire OAuth2 client credentials token from Keycloak
#
# Usage:
#   ./get_token.sh readonly        — Get token for readonly-client
#   ./get_token.sh readwrite       — Get token for readwrite-client
#   ./get_token.sh admin           — Get token for admin-client
#   ./get_token.sh readonly raw    — Print raw token string only (for use in variables)
# ─────────────────────────────────────────────────────────────────────────────

KEYCLOAK_URL="http://localhost:8080"
REALM="lab-realm"
TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

CLIENT="${1:-readonly}"
MODE="${2:-pretty}"

case "$CLIENT" in
    readonly)
        CLIENT_ID="readonly-client"
        CLIENT_SECRET="readonly-client-secret"
        ;;
    readwrite)
        CLIENT_ID="readwrite-client"
        CLIENT_SECRET="readwrite-client-secret"
        ;;
    admin)
        CLIENT_ID="admin-client"
        CLIENT_SECRET="admin-client-secret"
        ;;
    *)
        echo "Unknown client: $CLIENT"
        echo "Usage: $0 [readonly|readwrite|admin] [raw]"
        exit 1
        ;;
esac

RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}")

if [ "$MODE" = "raw" ]; then
    echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
    exit 0
fi

ACCESS_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token','ERROR'))")
EXPIRES_IN=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('expires_in','?'))")
TOKEN_TYPE=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token_type','?'))")

if [ "$ACCESS_TOKEN" = "ERROR" ]; then
    echo "[ERROR] Token request failed"
    echo "Response: $RESPONSE"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo " Token acquired for: $CLIENT_ID"
echo "════════════════════════════════════════════════════════"
echo " Token type    : $TOKEN_TYPE"
echo " Expires in    : ${EXPIRES_IN}s"
echo " Token endpoint: $TOKEN_ENDPOINT"
echo ""
echo " Full token:"
echo "$ACCESS_TOKEN"
echo ""
echo " Decoded header:"
echo "$ACCESS_TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo ""
echo " Decoded payload:"
echo "$ACCESS_TOKEN" | cut -d'.' -f2 | python3 -c "
import sys, base64, json
b64 = sys.stdin.read().strip()
b64 += '=' * (4 - len(b64) % 4)
decoded = base64.urlsafe_b64decode(b64)
print(json.dumps(json.loads(decoded), indent=2))
"
echo ""
echo " Export for use in subsequent commands:"
echo " export TOKEN=\"$ACCESS_TOKEN\""
echo "════════════════════════════════════════════════════════"
