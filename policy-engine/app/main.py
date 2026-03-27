from fastapi import FastAPI
from pydantic import BaseModel
import yaml
import os

app = FastAPI(title="Policy Engine")

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

    # Sort by endpoint length — longest match first
    # So /admin/users is checked before /admin
    sorted_policies = sorted(policies, key=lambda p: len(p["endpoint"]), reverse=True)

    for policy in sorted_policies:
        endpoint_match = (
            req.endpoint == policy["endpoint"] or
            req.endpoint.startswith(policy["endpoint"] + "/") or
            req.endpoint == policy["endpoint"].rstrip("/")
        )
        method_match = (
            policy["method"].upper() == "ANY" or
            policy["method"].upper() == req.method.upper()
        )

        if endpoint_match and method_match:
            conditions = policy["conditions"]

            if req.trust_score < conditions.get("min_trust_score", 0):
                return {
                    "verdict": "BLOCK",
                    "policy": policy["name"],
                    "reason": policy["reason"]
                }

            if conditions.get("require_token") and not req.token:
                return {
                    "verdict": "BLOCK",
                    "policy": policy["name"],
                    "reason": "Token required but not provided"
                }

            # Policy matched and conditions passed
            return {
                "verdict": "ALLOW",
                "policy": policy["name"],
                "reason": "Policy matched and conditions satisfied"
            }

    return {
        "verdict": "ALLOW",
        "policy": "default",
        "reason": "No policy matched"
    }
