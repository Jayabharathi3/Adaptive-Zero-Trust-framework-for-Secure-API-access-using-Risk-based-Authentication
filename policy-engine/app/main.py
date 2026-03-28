from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
import yaml
import os

app = FastAPI(title="Policy Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

POLICY_FILE = "/app/policies.yaml"


def load_policies():
    try:
        with open(POLICY_FILE, "r") as f:
            return yaml.safe_load(f).get("policies", [])
    except:
        return []


class EvaluateRequest(BaseModel):
    endpoint: str
    method: str
    trust_score: float
    token: str


@app.get("/health")
async def health():
    return {"status": "policy engine running", "module": 6}


@app.post("/evaluate")
async def evaluate(req: EvaluateRequest):
    policies = load_policies()

    for policy in policies:
        # Check if endpoint matches
        if policy["endpoint"] == "/" or policy["endpoint"] in req.endpoint:
            conditions = policy["conditions"]
            min_score = conditions.get("min_trust_score", 0)
            require_token = conditions.get("require_token", False)

            # If min_trust_score is 0 — always allow regardless of score
            if min_score == 0:
                return {
                    "verdict": "ALLOW",
                    "policy": policy["name"],
                    "reason": policy["reason"]
                }

            # Check token requirement
            if require_token and not req.token:
                return {
                    "verdict": "BLOCK",
                    "policy": policy["name"],
                    "reason": "Token required but not provided"
                }

            # Check trust score
            if req.trust_score < min_score:
                return {
                    "verdict": "BLOCK",
                    "policy": policy["name"],
                    "reason": policy["reason"]
                }

            # All conditions passed
            return {
                "verdict": "ALLOW",
                "policy": policy["name"],
                "reason": policy["reason"]
            }

    # No policy matched — allow by default
    return {
        "verdict": "ALLOW",
        "policy": "default",
        "reason": "No blocking policy matched"
    }
