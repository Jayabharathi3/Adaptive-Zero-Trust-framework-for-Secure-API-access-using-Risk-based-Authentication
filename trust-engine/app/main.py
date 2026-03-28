from fastapi import FastAPI
from pydantic import BaseModel
from fastapi import WebSocket
from fastapi.websockets import WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import redis
import os
import time

app = FastAPI(title="Trust Scoring Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379"))


class ScoreRequest(BaseModel):
    token: str
    ip: str
    endpoint: str
    method: str


def score_token(token: str) -> int:
    if not token:
        return -40
    # Detect attack tokens
    if "attack" in token.lower():
        return -40
    if "flood" in token.lower():
        return -40
    if "bola" in token.lower():
        return -40
    if "forge" in token.lower():
        return -40
    # none algorithm attack
    if token.startswith("eyJhbGciOiJub25lIn0"):
        return -50
    # Valid JWT structure check
    parts = token.split(".")
    if len(parts) != 3:
        return -30
    # Looks like a proper JWT
    return 20


def score_ip(ip: str) -> int:
    suspicious_ips = ["192.168.1.100", "10.0.0.99"]
    if ip in suspicious_ips:
        return -30
    return 10


def score_rate(ip: str) -> int:
    key = f"rate:{ip}"
    count = redis_client.incr(key)
    redis_client.expire(key, 60)
    if count > 50:      # increased threshold
        return -60
    elif count > 30:    # increased threshold
        return -30
    elif count > 15:    # increased threshold
        return -20
    return 10


def score_endpoint(endpoint: str) -> int:
    sensitive = ["/admin", "/payments", "/users/delete"]
    if any(s in endpoint for s in sensitive):
        return -10
    return 5


@app.get("/health")
async def health():
    return {"status": "trust engine running", "module": 2}


@app.post("/score")
async def score_request(req: ScoreRequest):
    base_score = 50
    token_score = score_token(req.token)
    ip_score = score_ip(req.ip)
    rate_score = score_rate(req.ip)
    endpoint_score = score_endpoint(req.endpoint)

    final_score = base_score + token_score + ip_score + rate_score + endpoint_score
    final_score = max(0, min(100, final_score))

    if final_score >= 70:
        verdict = "ALLOW"
    elif final_score >= 50:
        verdict = "CHALLENGE"
    else:
        verdict = "BLOCK"

    # Store in redis for dashboard
    redis_client.lpush("request_log", str({
        "ip": req.ip,
        "endpoint": req.endpoint,
        "score": final_score,
        "verdict": verdict,
        "time": time.time()
    }))
    redis_client.ltrim("request_log", 0, 99)

    return {
        "score": final_score,
        "verdict": verdict,
        "breakdown": {
            "base": base_score,
            "token": token_score,
            "ip": ip_score,
            "rate": rate_score,
            "endpoint": endpoint_score
        }
    }


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    last_seen = None
    try:
        while True:
            await asyncio.sleep(0.5)
            try:
                entry = redis_client.lindex("request_log", 0)
                if entry and entry != last_seen:
                    last_seen = entry
                    await ws.send_text(entry)
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
