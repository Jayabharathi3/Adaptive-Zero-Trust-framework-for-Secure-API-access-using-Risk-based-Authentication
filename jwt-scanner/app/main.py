from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import base64
import json
import hmac
import hashlib

app = FastAPI(title="JWT Vulnerability Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    token: str


def decode_part(part: str) -> dict:
    # Add padding
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    except:
        return {}


def test_none_algorithm(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"test": "none_algorithm", "result": "SAFE", "detail": "Invalid token format"}

        header = decode_part(parts[0])
        alg = header.get("alg", "").lower()

        if alg == "none":
            return {
                "test": "none_algorithm",
                "result": "VULNERABLE",
                "detail": "Token uses 'none' algorithm — no signature verification, attacker can forge any payload"
            }

        # Try crafting a none-algorithm version
        forged_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()

        return {
            "test": "none_algorithm",
            "result": "SAFE",
            "detail": f"Token uses {alg.upper()} algorithm correctly"
        }
    except Exception as e:
        return {"test": "none_algorithm", "result": "ERROR", "detail": str(e)}


def test_weak_secret(token: str) -> dict:
    common_secrets = [
        "secret", "password", "123456", "admin",
        "key", "test", "qwerty", "letmein",
        "changeme", "supersecret", "jwt_secret",
        "mysecret", "private", "token"
    ]
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"test": "weak_secret_bruteforce", "result": "SAFE", "detail": "Invalid token"}

        header = decode_part(parts[0])
        alg = header.get("alg", "").upper()

        if alg != "HS256":
            return {
                "test": "weak_secret_bruteforce",
                "result": "SKIP",
                "detail": f"Only applies to HS256, token uses {alg}"
            }

        message = f"{parts[0]}.{parts[1]}".encode()

        for secret in common_secrets:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message, hashlib.sha256).digest()
            ).rstrip(b"=").decode()

            if sig == parts[2]:
                return {
                    "test": "weak_secret_bruteforce",
                    "result": "VULNERABLE",
                    "detail": f"Weak secret found: '{secret}' — attacker can forge any token"
                }

        return {
            "test": "weak_secret_bruteforce",
            "result": "SAFE",
            "detail": "Secret not found in common dictionary (14 secrets tested)"
        }
    except Exception as e:
        return {"test": "weak_secret_bruteforce", "result": "ERROR", "detail": str(e)}


def test_algorithm_confusion(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"test": "algorithm_confusion", "result": "SAFE", "detail": "Invalid token"}

        header = decode_part(parts[0])
        alg = header.get("alg", "").upper()

        if alg == "RS256":
            return {
                "test": "algorithm_confusion_RS256_to_HS256",
                "result": "VULNERABLE",
                "detail": "RS256 token detected — vulnerable to algorithm confusion. Attacker can use public key as HMAC secret to forge tokens"
            }

        return {
            "test": "algorithm_confusion_RS256_to_HS256",
            "result": "SAFE",
            "detail": f"Token uses {alg}, not RS256 — algorithm confusion not applicable"
        }
    except Exception as e:
        return {"test": "algorithm_confusion", "result": "ERROR", "detail": str(e)}


def test_expiry(token: str) -> dict:
    try:
        import time
        parts = token.split(".")
        if len(parts) != 3:
            return {"test": "expiry_validation", "result": "SAFE", "detail": "Invalid token"}

        payload = decode_part(parts[1])

        if "exp" not in payload:
            return {
                "test": "expiry_validation",
                "result": "VULNERABLE",
                "detail": "Token has no expiry (exp) claim — token never expires, valid forever"
            }

        exp = payload["exp"]
        now = time.time()

        if exp < now:
            return {
                "test": "expiry_validation",
                "result": "VULNERABLE",
                "detail": f"Token is EXPIRED (expired {int((now - exp) / 60)} minutes ago) — server should reject this"
            }

        return {
            "test": "expiry_validation",
            "result": "SAFE",
            "detail": f"Token has valid expiry claim"
        }
    except Exception as e:
        return {"test": "expiry_validation", "result": "ERROR", "detail": str(e)}


def test_sensitive_data(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"test": "sensitive_data_exposure", "result": "SAFE", "detail": "Invalid token"}

        payload = decode_part(parts[1])
        sensitive_keys = ["password", "secret",
                          "credit_card", "ssn", "cvv", "pin", "private_key"]
        found = [k for k in sensitive_keys if k in str(payload).lower()]

        if found:
            return {
                "test": "sensitive_data_exposure",
                "result": "VULNERABLE",
                "detail": f"Sensitive fields found in payload: {found} — JWT payload is base64 encoded, NOT encrypted"
            }

        return {
            "test": "sensitive_data_exposure",
            "result": "SAFE",
            "detail": "No sensitive data detected in payload"
        }
    except Exception as e:
        return {"test": "sensitive_data_exposure", "result": "ERROR", "detail": str(e)}


@app.get("/health")
async def health():
    return {"status": "jwt scanner running", "module": 3}


@app.post("/scan")
async def scan_token(req: ScanRequest):
    token = req.token.strip()

    # Decode header and payload for display
    parts = token.split(".")
    header = decode_part(parts[0]) if len(parts) >= 1 else {}
    payload = decode_part(parts[1]) if len(parts) >= 2 else {}

    # Run all tests
    vulnerabilities = [
        test_none_algorithm(token),
        test_weak_secret(token),
        test_algorithm_confusion(token),
        test_expiry(token),
        test_sensitive_data(token),
    ]

    # Calculate risk level
    vuln_count = sum(1 for v in vulnerabilities if v["result"] == "VULNERABLE")

    if vuln_count >= 3:
        risk_level = "CRITICAL"
    elif vuln_count == 2:
        risk_level = "HIGH"
    elif vuln_count == 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "SAFE"

    return {
        "risk_level": risk_level,
        "vulnerabilities_found": vuln_count,
        "header": header,
        "payload": payload,
        "vulnerabilities": vulnerabilities
    }
