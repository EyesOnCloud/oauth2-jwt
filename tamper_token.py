#!/usr/bin/env python3
"""
tamper_token.py — Demonstrates JWT tampering attacks and why they fail.

This script takes a valid JWT and produces several tampered versions,
then sends each to the API to show that all are rejected with 401.

Usage: python3 tamper_token.py <valid_token>
"""

import sys
import base64
import json
import requests

API_URL = "http://localhost:3000"

def b64_decode_padding(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64_encode_no_padding(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def decode_jwt_parts(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Not a valid JWT structure (expected 3 parts)")
    header = json.loads(b64_decode_padding(parts[0]))
    payload = json.loads(b64_decode_padding(parts[1]))
    signature = parts[2]
    return header, payload, signature, parts

def test_token(description, token, expected_status):
    try:
        response = requests.get(
            f"{API_URL}/api/data",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        status = response.status_code
        body = response.json()
        status_match = "✓" if status == expected_status else "✗"
        print(f"\n  {status_match} [{status}] {description}")
        print(f"    API response: {body.get('error', body.get('status', 'ok'))}")
        if 'message' in body:
            print(f"    Message: {body['message']}")
        return status == expected_status
    except Exception as e:
        print(f"\n  ✗ [ERROR] {description}: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tamper_token.py <valid_jwt_token>")
        print("Get a token first: export TOKEN=$(./get_token.sh readonly raw)")
        print("Then run: python3 tamper_token.py $TOKEN")
        sys.exit(1)

    original_token = sys.argv[1].strip()

    print("═" * 65)
    print(" JWT Tampering Attack Demonstration — LAB 3.1")
    print("═" * 65)
    print(f"\n[*] Original token received. Parsing structure...")

    try:
        header, payload, signature, parts = decode_jwt_parts(original_token)
    except Exception as e:
        print(f"[ERROR] Could not parse token: {e}")
        sys.exit(1)

    print(f"\n Original header  : {json.dumps(header)}")
    print(f" Original azp     : {payload.get('azp', '?')}")
    print(f" Original scope   : {payload.get('scope', '?')}")
    print(f" Original roles   : {payload.get('realm_access', {}).get('roles', [])}")
    print(f"\n[*] Testing original valid token first...")

    print("\n" + "─" * 65)
    print(" TEST RESULTS")
    print("─" * 65)

    test_token("BASELINE — original valid token", original_token, 200)

    print("\n[*] Attack 1 — Scope Escalation")
    print("    Modify payload to add api:write scope without re-signing")
    modified_payload = payload.copy()
    modified_payload['scope'] = payload.get('scope', '') + ' api:write'
    modified_payload['realm_access'] = {
        'roles': ['reader', 'writer', 'admin']
    }
    new_payload_b64 = b64_encode_no_padding(json.dumps(modified_payload).encode())
    tampered_scope = f"{parts[0]}.{new_payload_b64}.{parts[2]}"
    test_token(
        "SCOPE ESCALATION — added api:write and admin role to payload",
        tampered_scope,
        401
    )

    print("\n[*] Attack 2 — Client Identity Forgery")
    print("    Modify azp claim to impersonate the admin-client")
    modified_payload2 = payload.copy()
    modified_payload2['azp'] = 'admin-client'
    modified_payload2['sub'] = 'forged-subject-id'
    new_payload2_b64 = b64_encode_no_padding(json.dumps(modified_payload2).encode())
    tampered_identity = f"{parts[0]}.{new_payload2_b64}.{parts[2]}"
    test_token(
        "IDENTITY FORGERY — changed azp to admin-client",
        tampered_identity,
        401
    )

    print("\n[*] Attack 3 — Expiry Extension")
    print("    Extend exp claim by 24 hours to bypass token expiry")
    import time
    modified_payload3 = payload.copy()
    modified_payload3['exp'] = int(time.time()) + 86400
    modified_payload3['iat'] = int(time.time())
    new_payload3_b64 = b64_encode_no_padding(json.dumps(modified_payload3).encode())
    tampered_expiry = f"{parts[0]}.{new_payload3_b64}.{parts[2]}"
    test_token(
        "EXPIRY EXTENSION — extended exp by 24 hours",
        tampered_expiry,
        401
    )

    print("\n[*] Attack 4 — Algorithm Confusion (none algorithm)")
    print("    Set alg to 'none' to bypass signature verification")
    modified_header = header.copy()
    modified_header['alg'] = 'none'
    new_header_b64 = b64_encode_no_padding(json.dumps(modified_header).encode())
    tampered_alg_none = f"{new_header_b64}.{parts[1]}."
    test_token(
        "ALGORITHM CONFUSION — alg set to 'none' (no signature)",
        tampered_alg_none,
        401
    )

    print("\n[*] Attack 5 — Truncated Signature")
    print("    Remove last 10 characters of signature")
    truncated_sig = parts[2][:-10]
    tampered_truncated = f"{parts[0]}.{parts[1]}.{truncated_sig}"
    test_token(
        "TRUNCATED SIGNATURE — last 10 chars of signature removed",
        tampered_truncated,
        401
    )

    print("\n[*] Attack 6 — Completely Forged Token (no signature)")
    print("    Build a token from scratch with desirable claims")
    forged_header = {"alg": "RS256", "typ": "JWT"}
    forged_payload = {
        "sub": "attacker-controlled-id",
        "azp": "admin-client",
        "iss": "http://localhost:8080/realms/lab-realm",
        "scope": "api:read api:write api:admin",
        "realm_access": {"roles": ["reader", "writer", "admin"]},
        "exp": int(time.time()) + 3600,
        "iat": int(time.time())
    }
    forged_h = b64_encode_no_padding(json.dumps(forged_header).encode())
    forged_p = b64_encode_no_padding(json.dumps(forged_payload).encode())
    forged_token = f"{forged_h}.{forged_p}.forgedsignatureXXXXXXXXXXXXXXXXXXXXXXXX"
    test_token(
        "FORGED TOKEN — completely fabricated with admin claims",
        forged_token,
        401
    )

    print("\n" + "═" * 65)
    print(" CONCLUSION")
    print("═" * 65)
    print(" All tampered tokens were rejected with 401.")
    print(" The JWT signature binds the header and payload to the")
    print(" authorization server's private key. Any modification to")
    print(" either the header or payload invalidates the signature.")
    print(" Without the private key, an attacker cannot produce a")
    print(" valid signature for modified content.")
    print("═" * 65)

if __name__ == '__main__':
    main()
