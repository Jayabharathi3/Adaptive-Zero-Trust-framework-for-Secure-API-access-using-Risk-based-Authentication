from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import asyncio
import time

app = FastAPI(title="Attack Simulator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attacks go through GATEWAY → victim API
GATEWAY_URL = "http://gateway:8000"
# Direct victim API calls (bypass gateway — shows what's exposed)
VICTIM_URL  = "http://victim-api:8005"

# ── Simulated user database ──────────────────────────────────────
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "admin"},
    2: {"id": 2, "name": "Bob",   "email": "bob@example.com",   "role": "user"},
    3: {"id": 3, "name": "Carol", "email": "carol@example.com", "role": "user"},
    4: {"id": 4, "name": "Dave",  "email": "dave@example.com",  "role": "user"},
    5: {"id": 5, "name": "Eve",   "email": "eve@example.com",   "role": "user"},
}

class AttackRequest(BaseModel):
    intensity: int = 5   # 1-10 scale

# ── Helper — send one request through gateway ────────────────────
async def send_request(client: httpx.AsyncClient, method: str, path: str, token: str = "", json: dict = None):
    try:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = await client.request(
            method,
            f"{GATEWAY_URL}{path}",
            headers=headers,
            json=json,
            timeout=5.0
        )
        return {
            "path": path,
            "status": response.status_code,
            "verdict": response.headers.get("X-Verdict", "UNKNOWN"),
            "trust_score": response.headers.get("X-Trust-Score", "N/A"),
            "blocked": response.status_code == 403
        }
    except Exception as e:
        return {"path": path, "status": "ERROR", "verdict": "ERROR", "trust_score": "N/A", "blocked": False, "error": str(e)}

@app.get("/health")
async def health():
    return {"status": "attack simulator running", "module": 4}

# ── Attack 1 — BOLA (Broken Object Level Authorization) ──────────
@app.post("/attack/bola")
async def bola_attack(req: AttackRequest):
    """
    BOLA = attacker tries to access other users' data
    by simply changing the user ID in the URL.
    Real OWASP API Top 10 #1 vulnerability.
    """
    results = []
    attacker_token = "attacker.fake.token"

    async with httpx.AsyncClient() as client:
        for user_id in range(1, req.intensity + 1):
            result = await send_request(
                client, "GET", f"/users/{user_id}", attacker_token
            )
            result["attack_type"] = "BOLA"
            result["description"] = f"Attacker trying to read user {user_id}'s data"
            results.append(result)
            await asyncio.sleep(0.1)

    blocked = sum(1 for r in results if r["blocked"])
    return {
        "attack": "BOLA — Broken Object Level Authorization",
        "owasp": "API Security Top 10 #1",
        "requests_sent": len(results),
        "blocked": blocked,
        "allowed": len(results) - blocked,
        "results": results
    }

# ── Attack 2 — Flood / Rate Limit Abuse ─────────────────────────
@app.post("/attack/flood")
async def flood_attack(req: AttackRequest):
    """
    Sends a burst of rapid requests to trigger rate limiting.
    Simulates DDoS or credential stuffing attempts.
    """
    results = []
    num_requests = req.intensity * 5  # intensity 10 = 50 requests

    async with httpx.AsyncClient() as client:
        tasks = [
            send_request(client, "GET", "/users", "flood.attack.token")
            for _ in range(num_requests)
        ]
        results = await asyncio.gather(*tasks)

    results = [dict(r, attack_type="FLOOD") for r in results]
    blocked = sum(1 for r in results if r["blocked"])

    return {
        "attack": "Rate Limit Flood Attack",
        "owasp": "API Security Top 10 #4",
        "requests_sent": len(results),
        "blocked": blocked,
        "allowed": len(results) - blocked,
        "results": list(results)
    }

# ── Attack 3 — Broken Auth (Expired Token Replay) ───────────────
@app.post("/attack/replay")
async def replay_attack(req: AttackRequest):
    """
    Replays expired or invalid tokens to test
    whether the server correctly rejects them.
    """
    bad_tokens = [
        "",                                      # No token
        "expired.token.here",                    # Fake expired
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", # alg=none forged
        "admin.admin.admin",                     # Guessed token
        "Bearer Bearer token",                   # Malformed
    ]

    results = []
    async with httpx.AsyncClient() as client:
        for token in bad_tokens[:req.intensity]:
            result = await send_request(
                client, "GET", "/admin", token
            )
            result["attack_type"] = "REPLAY"
            result["token_used"] = token[:30] + "..." if len(token) > 30 else token
            result["description"] = "Replaying invalid/expired token"
            results.append(result)
            await asyncio.sleep(0.2)

    blocked = sum(1 for r in results if r["blocked"])
    return {
        "attack": "Broken Auth — Token Replay Attack",
        "owasp": "API Security Top 10 #2",
        "requests_sent": len(results),
        "blocked": blocked,
        "allowed": len(results) - blocked,
        "results": results
    }

# ── Attack 4 — Mass Assignment ───────────────────────────────────
@app.post("/attack/mass-assignment")
async def mass_assignment_attack(req: AttackRequest):
    """
    Sends extra fields the API shouldn't accept —
    like trying to set role=admin or is_admin=true.
    Tests if the API blindly accepts all input fields.
    """
    payloads = [
        {"username": "attacker", "role": "admin"},
        {"username": "attacker", "is_admin": True},
        {"username": "attacker", "trust_score": 100},
        {"username": "attacker", "permissions": ["read", "write", "delete"]},
        {"username": "attacker", "id": 1, "override": True},
    ]

    results = []
    async with httpx.AsyncClient() as client:
        for payload in payloads[:req.intensity]:
            result = await send_request(
                client, "POST", "/users/register",
                "mass.assign.token", payload
            )
            result["attack_type"] = "MASS_ASSIGNMENT"
            result["payload_sent"] = payload
            result["description"] = "Injecting privileged fields into request"
            results.append(result)
            await asyncio.sleep(0.1)

    blocked = sum(1 for r in results if r["blocked"])
    return {
        "attack": "Mass Assignment Attack",
        "owasp": "API Security Top 10 #6",
        "requests_sent": len(results),
        "blocked": blocked,
        "allowed": len(results) - blocked,
        "results": results
    }

# ── Combined — run all attacks in sequence ───────────────────────
@app.post("/attack/all")
async def all_attacks(req: AttackRequest):
    bola    = await bola_attack(req)
    flood   = await flood_attack(AttackRequest(intensity=3))
    replay  = await replay_attack(req)
    mass    = await mass_assignment_attack(req)

    total_sent    = bola["requests_sent"] + flood["requests_sent"] + replay["requests_sent"] + mass["requests_sent"]
    total_blocked = bola["blocked"] + flood["blocked"] + replay["blocked"] + mass["blocked"]

    return {
        "summary": {
            "total_requests": total_sent,
            "total_blocked": total_blocked,
            "total_allowed": total_sent - total_blocked,
            "block_rate": f"{round((total_blocked / total_sent) * 100)}%" if total_sent else "0%"
        },
        "attacks": [bola, flood, replay, mass]
    }