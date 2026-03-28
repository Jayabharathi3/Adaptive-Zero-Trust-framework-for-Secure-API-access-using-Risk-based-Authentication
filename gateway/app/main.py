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
VICTIM_API_URL = os.getenv("VICTIM_API_URL",    "http://juice-shop:3000")


@app.get("/health")
async def health():
    return {"status": "gateway running", "module": 1}


async def check_zero_trust(token: str, client_ip: str, endpoint: str, method: str):
    """Run trust scoring + policy check. Returns (score, verdict, reason)."""
    async with httpx.AsyncClient() as client:

        score_resp = await client.post(
            f"{TRUST_ENGINE_URL}/score",
            json={"token": token, "ip": client_ip,
                  "endpoint": endpoint, "method": method},
            timeout=5.0
        )
        score_data = score_resp.json()
        trust_score = score_data.get("score", 0)
        trust_verdict = score_data.get("verdict", "BLOCK")

        policy_resp = await client.post(
            f"{POLICY_ENGINE_URL}/evaluate",
            json={"endpoint": endpoint, "method": method,
                  "trust_score": trust_score, "token": token},
            timeout=5.0
        )
        policy_data = policy_resp.json()
        policy_verdict = policy_data.get("verdict", "ALLOW")
        policy_reason = policy_data.get("reason", "No policy matched")

    if trust_verdict == "BLOCK" or policy_verdict == "BLOCK":
        final_verdict = "BLOCK"
    elif trust_verdict == "CHALLENGE" or policy_verdict == "CHALLENGE":
        final_verdict = "CHALLENGE"
    else:
        final_verdict = "ALLOW"

    return trust_score, final_verdict, policy_reason


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway_handler(path: str, request: Request):
    endpoint = f"/{path}"
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    client_ip = request.client.host if request.client else "127.0.0.1"
    method = request.method

    # ── Zero Trust checks ────────────────────────────────────────
    try:
        trust_score, verdict, reason = await check_zero_trust(
            token, client_ip, endpoint, method
        )
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": f"Gateway error: {str(e)}"})

    # ── Block ────────────────────────────────────────────────────
    if verdict == "BLOCK":
        return JSONResponse(
            status_code=403,
            content={
                "verdict":     "BLOCK",
                "trust_score": trust_score,
                "reason":      reason,
                "endpoint":    endpoint
            }
        )

    # ── Forward to Juice Shop ────────────────────────────────────
    try:
        body = await request.body()
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=f"{VICTIM_API_URL}{endpoint}",
                headers={k: v for k, v in request.headers.items()
                         if k.lower() not in ["host", "content-length"]},
                content=body,
                timeout=10.0
            )
            try:
                content = response.json()
            except Exception:
                content = {"raw": response.text}

            return JSONResponse(
                status_code=response.status_code,
                content=content,
                headers={
                    "X-Trust-Score": str(trust_score),
                    "X-Verdict":     verdict
                }
            )
    except Exception as e:
        return JSONResponse(
            status_code=502,
            content={"error": f"Forwarding failed: {str(e)}"}
        )
