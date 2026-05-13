import os
import time
import logging
import requests
import jwt
from jwt import PyJWKClient, ExpiredSignatureError, InvalidSignatureError, DecodeError
from flask import Flask, request, jsonify
from functools import wraps

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

KEYCLOAK_URL = os.environ.get('KEYCLOAK_URL', 'http://keycloak:8080')
KEYCLOAK_REALM = os.environ.get('KEYCLOAK_REALM', 'lab-realm')
JWKS_URI = os.environ.get('JWKS_URI', f'{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs')
ISSUER = os.environ.get('ISSUER', f'{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}')

_jwks_client = None
_request_log = []

def get_jwks_client():
    """
    Returns a cached JWKS client that fetches Keycloak's public keys.
    The JWKS (JSON Web Key Set) endpoint exposes the authorization server's
    public keys. The API uses these to verify JWT signatures without needing
    to contact Keycloak on every request — verification is done locally using
    the public key mathematics.
    """
    global _jwks_client
    if _jwks_client is None:
        logger.info(f"[JWKS] Initializing JWKS client from: {JWKS_URI}")
        _jwks_client = PyJWKClient(JWKS_URI, cache_keys=True)
    return _jwks_client

def extract_token():
    """
    Extracts the Bearer token from the Authorization header.
    RFC 6750 defines the Bearer token format: 'Authorization: Bearer <token>'
    Any deviation from this format is rejected before JWT parsing begins.
    """
    auth_header = request.headers.get('Authorization', '')
    if not auth_header:
        return None, "Authorization header missing"
    if not auth_header.startswith('Bearer '):
        return None, "Authorization header must use Bearer scheme"
    token = auth_header[7:].strip()
    if not token:
        return None, "Bearer token is empty"
    return token, None

def validate_jwt(token):
    """
    Full JWT validation pipeline. Every check here corresponds to a real
    attack vector that this validation defeats.

    Check 1 — Signature verification: Uses Keycloak's public key from JWKS.
    Defeats: Forged tokens, tokens signed with attacker keys, 'none' algorithm attack.

    Check 2 — Expiry (exp claim): Verified by PyJWT automatically.
    Defeats: Stolen tokens used after their validity window.

    Check 3 — Issuer (iss claim): Verified against configured ISSUER.
    Defeats: Tokens issued by a different authorization server (confused deputy).

    Check 4 — Audience (aud claim): Not enforced strictly in this lab for
    simplicity, but noted as a required check in production.
    Defeats: Tokens intended for one service being replayed against another.

    Returns (payload_dict, error_string) — one will always be None.
    """
    try:
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": False
            }
        )

        logger.info(f"[JWT] Valid token for client: {payload.get('azp', 'unknown')} | "
                   f"Scopes: {payload.get('scope', 'none')} | "
                   f"Roles: {payload.get('realm_access', {}).get('roles', [])}")

        return payload, None

    except ExpiredSignatureError as e:
        exp_time = None
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            exp_time = unverified.get('exp')
        except Exception:
            pass
        error_msg = f"Token has expired"
        if exp_time:
            error_msg += f" at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(exp_time))}"
        logger.warning(f"[JWT] REJECTED — Expired token")
        return None, error_msg

    except InvalidSignatureError:
        logger.warning(f"[JWT] REJECTED — Invalid signature (tampered token)")
        return None, "Token signature is invalid — token may have been tampered with"

    except DecodeError as e:
        logger.warning(f"[JWT] REJECTED — Malformed token: {e}")
        return None, f"Token is malformed: {str(e)}"

    except jwt.exceptions.InvalidIssuerError:
        logger.warning(f"[JWT] REJECTED — Wrong issuer")
        return None, f"Token issuer does not match expected issuer: {ISSUER}"

    except Exception as e:
        logger.error(f"[JWT] Unexpected validation error: {type(e).__name__}: {e}")
        return None, f"Token validation failed: {str(e)}"

def require_auth(required_scopes=None, required_roles=None):
    """
    Decorator factory that creates endpoint-specific authorization middleware.

    required_scopes: list of OAuth2 scope strings that must ALL be present
    required_roles: list of Keycloak realm roles where at least ONE must be present

    Usage:
        @require_auth(required_scopes=['api:read'])
        @require_auth(required_scopes=['api:write'], required_roles=['writer'])
        @require_auth(required_roles=['admin'])
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            request_entry = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "method": request.method,
                "path": request.path,
                "remote_addr": request.remote_addr,
                "required_scopes": required_scopes,
                "required_roles": required_roles,
                "outcome": None,
                "client_id": None,
                "rejection_reason": None
            }

            token, extract_error = extract_token()
            if not token:
                request_entry["outcome"] = "rejected_no_token"
                request_entry["rejection_reason"] = extract_error
                _request_log.append(request_entry)
                return jsonify({
                    "error": "unauthorized",
                    "message": extract_error,
                    "hint": "Include 'Authorization: Bearer <token>' header"
                }), 401

            payload, validation_error = validate_jwt(token)
            if not payload:
                request_entry["outcome"] = "rejected_invalid_token"
                request_entry["rejection_reason"] = validation_error
                _request_log.append(request_entry)

                if "expired" in validation_error.lower():
                    return jsonify({
                        "error": "token_expired",
                        "message": validation_error,
                        "hint": "Request a new token using the client credentials flow"
                    }), 401
                elif "signature" in validation_error.lower() or "tampered" in validation_error.lower():
                    return jsonify({
                        "error": "token_invalid",
                        "message": validation_error,
                        "hint": "Token signature verification failed — do not modify JWT tokens"
                    }), 401
                else:
                    return jsonify({
                        "error": "token_invalid",
                        "message": validation_error
                    }), 401

            request_entry["client_id"] = payload.get('azp', 'unknown')

            token_scopes = set(payload.get('scope', '').split())
            token_roles = set(payload.get('realm_access', {}).get('roles', []))

            if required_scopes:
                missing_scopes = [s for s in required_scopes if s not in token_scopes]
                if missing_scopes:
                    request_entry["outcome"] = "rejected_insufficient_scope"
                    request_entry["rejection_reason"] = f"Missing scopes: {missing_scopes}"
                    _request_log.append(request_entry)
                    return jsonify({
                        "error": "insufficient_scope",
                        "message": f"Token does not have required scope(s): {missing_scopes}",
                        "token_scopes": list(token_scopes),
                        "required_scopes": required_scopes,
                        "hint": "Use a client that has been granted the required scope"
                    }), 403

            if required_roles:
                has_required_role = any(r in token_roles for r in required_roles)
                if not has_required_role:
                    request_entry["outcome"] = "rejected_insufficient_role"
                    request_entry["rejection_reason"] = f"Required one of roles: {required_roles}"
                    _request_log.append(request_entry)
                    return jsonify({
                        "error": "insufficient_role",
                        "message": f"Token does not have any of the required role(s): {required_roles}",
                        "token_roles": list(token_roles),
                        "required_roles": required_roles,
                        "hint": "Use a client whose service account has the required realm role"
                    }), 403

            request_entry["outcome"] = "allowed"
            _request_log.append(request_entry)

            request.jwt_payload = payload
            return f(*args, **kwargs)

        return wrapper
    return decorator

# ─────────────────────────────────────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/public')
def public_endpoint():
    """No authentication required. Baseline to confirm API is running."""
    return jsonify({
        "endpoint": "public",
        "message": "This endpoint requires no authentication",
        "keycloak_issuer": ISSUER,
        "jwks_uri": JWKS_URI,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }), 200

@app.route('/api/data')
@require_auth(required_scopes=['api:read'])
def read_data():
    """
    Read-only endpoint. Requires api:read scope.
    The readonly-client has this scope. The unauthenticated caller does not.
    """
    payload = request.jwt_payload
    return jsonify({
        "endpoint": "read",
        "status": "success",
        "data": [
            {"id": 1, "record": "Q1 Sales Report", "classification": "internal"},
            {"id": 2, "record": "Customer List 2024", "classification": "confidential"},
            {"id": 3, "record": "Infrastructure Inventory", "classification": "restricted"}
        ],
        "accessed_by": payload.get('azp', 'unknown'),
        "token_scopes": payload.get('scope', '').split(),
        "token_roles": payload.get('realm_access', {}).get('roles', []),
        "token_expires_at": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(payload.get('exp', 0))
        )
    }), 200

@app.route('/api/data', methods=['POST'])
@require_auth(required_scopes=['api:read', 'api:write'])
def write_data():
    """
    Write endpoint. Requires BOTH api:read AND api:write scopes.
    The readonly-client is rejected here with 403 Insufficient Scope.
    The readwrite-client succeeds.
    """
    payload = request.jwt_payload
    body = request.get_json() or {}
    return jsonify({
        "endpoint": "write",
        "status": "success",
        "message": "Record created successfully",
        "created_record": body,
        "created_by": payload.get('azp', 'unknown'),
        "token_scopes": payload.get('scope', '').split()
    }), 201

@app.route('/api/admin/users')
@require_auth(required_roles=['admin'])
def admin_users():
    """
    Admin endpoint. Requires the 'admin' realm role.
    Only the admin-client's service account has this role.
    The readwrite-client is rejected here with 403 Insufficient Role.
    Demonstrates role-based vs scope-based access control distinction.
    """
    payload = request.jwt_payload
    return jsonify({
        "endpoint": "admin",
        "status": "success",
        "users": [
            {"id": "sa-readonly", "client": "readonly-client", "roles": ["reader"]},
            {"id": "sa-readwrite", "client": "readwrite-client", "roles": ["reader", "writer"]},
            {"id": "sa-admin", "client": "admin-client", "roles": ["reader", "writer", "admin"]}
        ],
        "accessed_by": payload.get('azp', 'unknown'),
        "token_roles": payload.get('realm_access', {}).get('roles', [])
    }), 200

@app.route('/api/token-debug')
@require_auth(required_scopes=['api:read'])
def token_debug():
    """
    Returns the decoded JWT payload for inspection.
    Shows participants exactly what claims the token carries.
    In production this endpoint would not exist — exposing token internals
    is a security risk. It is included here for educational purposes.
    """
    payload = request.jwt_payload
    return jsonify({
        "endpoint": "token_debug",
        "decoded_payload": {
            "iss": payload.get('iss'),
            "sub": payload.get('sub'),
            "azp": payload.get('azp'),
            "exp": payload.get('exp'),
            "exp_human": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(payload.get('exp', 0))),
            "iat": payload.get('iat'),
            "iat_human": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(payload.get('iat', 0))),
            "scope": payload.get('scope'),
            "realm_access": payload.get('realm_access'),
            "typ": payload.get('typ')
        },
        "note": "This endpoint exposes token internals for lab purposes only"
    }), 200

@app.route('/api/audit-log')
@require_auth(required_roles=['admin'])
def audit_log():
    """
    Returns the API's internal request audit log.
    Shows every authorization decision made since the API started.
    Demonstrates that every 401/403 is an observable security event.
    """
    return jsonify({
        "total_requests": len(_request_log),
        "allowed": sum(1 for r in _request_log if r["outcome"] == "allowed"),
        "rejected": sum(1 for r in _request_log if r["outcome"] and r["outcome"].startswith("rejected")),
        "log": _request_log[-50:]
    }), 200

@app.route('/health')
def health():
    try:
        resp = requests.get(
            f'{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration',
            timeout=3
        )
        keycloak_ok = resp.status_code == 200
    except Exception:
        keycloak_ok = False

    return jsonify({
        "api": "ok",
        "keycloak_reachable": keycloak_ok,
        "issuer": ISSUER,
        "jwks_uri": JWKS_URI
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    logger.info(f"[STARTUP] Protected API starting on port {port}")
    logger.info(f"[STARTUP] JWKS URI: {JWKS_URI}")
    logger.info(f"[STARTUP] Issuer: {ISSUER}")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
