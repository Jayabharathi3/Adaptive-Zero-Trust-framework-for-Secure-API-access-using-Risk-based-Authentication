from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os

app = FastAPI(title="Zero Trust API Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TRUST_ENGINE_URL = os.getenv("TRUST_ENGINE_URL", "http://trust-engine:8001")
POLICY_ENGINE_URL = os.getenv("POLICY_ENGINE_URL", "http://policy-engine:8004")
VICTIM_API_URL = os.getenv("VICTIM_API_URL", "http://victim-api:8005")


@app.get("/health")
async def health():
    return {"status": "gateway running", "module": 1}


async def run_zero_trust_checks(token: str, client_ip: str, endpoint: str, method: str):
    async with httpx.AsyncClient() as client:
        score_response = await client.post(
            f"{TRUST_ENGINE_URL}/score",
            json={"token": token, "ip": client_ip,
                  "endpoint": endpoint, "method": method},
            timeout=5.0
        )
        score_data = score_response.json()
        trust_score = score_data.get("score", 0)
        trust_verdict = score_data.get("verdict", "BLOCK")

        policy_response = await client.post(
            f"{POLICY_ENGINE_URL}/evaluate",
            json={"endpoint": endpoint, "method": method,
                  "trust_score": trust_score, "token": token},
            timeout=5.0
        )
        policy_data = policy_response.json()
        policy_verdict = policy_data.get("verdict", "BLOCK")
        policy_reason = policy_data.get("reason", "Policy check failed")

    # Policy BLOCK overrides everything
    if policy_verdict == "BLOCK":
        final_verdict = "BLOCK"
    # Trust score BLOCK overrides if policy doesn't explicitly allow
    elif trust_verdict == "BLOCK" and policy_verdict != "ALLOW":
        final_verdict = "BLOCK"
    elif trust_verdict == "CHALLENGE" or policy_verdict == "CHALLENGE":
        final_verdict = "CHALLENGE"
    else:
        final_verdict = "ALLOW"

    return trust_score, final_verdict, policy_reason


# ── Specific routes FIRST — before the catch-all ─────────────────

@app.get("/api/users")
async def get_users(request: Request):
    # Still run zero trust checks
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    client_ip = request.client.host
    try:
        trust_score, verdict, reason = await run_zero_trust_checks(
            token, client_ip, "/api/users", "GET"
        )
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

    if verdict == "BLOCK":
        return JSONResponse(status_code=403, content={
            "verdict": "BLOCK",
            "trust_score": trust_score,
            "reason": reason
        })

    return JSONResponse(
        content={
            "users": [
                {"id": 1, "name": "Alice", "role": "admin"},
                {"id": 2, "name": "Bob", "role": "user"},
                {"id": 3, "name": "Charlie", "role": "user"}
            ]
        },
        headers={"X-Trust-Score": str(trust_score), "X-Verdict": verdict}
    )


@app.get("/api/users/{user_id}")
async def get_user(user_id: int, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    client_ip = request.client.host
    try:
        trust_score, verdict, reason = await run_zero_trust_checks(
            token, client_ip, f"/api/users/{user_id}", "GET"
        )
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

    if verdict == "BLOCK":
        return JSONResponse(status_code=403, content={
            "verdict": "BLOCK",
            "trust_score": trust_score,
            "reason": reason
        })

    return JSONResponse(
        content={"id": user_id, "name": "Alice", "role": "user"},
        headers={"X-Trust-Score": str(trust_score), "X-Verdict": verdict}
    )


@app.post("/api/admin")
async def admin_endpoint(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    client_ip = request.client.host
    try:
        trust_score, verdict, reason = await run_zero_trust_checks(
            token, client_ip, "/api/admin", "POST"
        )
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

    if verdict == "BLOCK":
        return JSONResponse(status_code=403, content={
            "verdict": "BLOCK",
            "trust_score": trust_score,
            "reason": reason
        })

    return JSONResponse(
        content={"message": "Admin access granted"},
        headers={"X-Trust-Score": str(trust_score), "X-Verdict": verdict}
    )


@app.post("/api/payments")
async def payments_endpoint(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    client_ip = request.client.host
    try:
        trust_score, verdict, reason = await run_zero_trust_checks(
            token, client_ip, "/api/payments", "POST"
        )
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

    if verdict == "BLOCK":
        return JSONResponse(status_code=403, content={
            "verdict": "BLOCK",
            "trust_score": trust_score,
            "reason": reason
        })

    return JSONResponse(
        content={"message": "Payment processed"},
        headers={"X-Trust-Score": str(trust_score), "X-Verdict": verdict}
    )


# ── Catch-all LAST — forwards everything else to victim API ──────

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def run_zero_trust_checks(token: str, client_ip: str, endpoint: str, method: str):
    async with httpx.AsyncClient() as client:
        score_response = await client.post(
            f"{TRUST_ENGINE_URL}/score",
            json={"token": token, "ip": client_ip,
                  "endpoint": endpoint, "method": method},
            timeout=5.0
        )
        score_data = score_response.json()
        trust_score = score_data.get("score", 0)
        trust_verdict = score_data.get("verdict", "BLOCK")

        policy_response = await client.post(
            f"{POLICY_ENGINE_URL}/evaluate",
            json={"endpoint": endpoint, "method": method,
                  "trust_score": trust_score, "token": token},
            timeout=5.0
        )
        policy_data = policy_response.json()
        policy_verdict = policy_data.get("verdict", "BLOCK")
        policy_reason = policy_data.get("reason", "Policy check failed")

    # Policy engine has final say
    # If policy explicitly ALLOWs — let it through regardless of trust score
    # If policy BLOCKs — block it
    # If policy ALLOWs but trust score is very low — still challenge/block
    if policy_verdict == "BLOCK":
        final_verdict = "BLOCK"
    elif policy_verdict == "ALLOW" and trust_score == 0:
        # Only block if score is literally 0
        final_verdict = "BLOCK"
    else:
        # Policy says ALLOW — respect it
        final_verdict = "ALLOW"

    return trust_score, final_verdict, policy_reason
