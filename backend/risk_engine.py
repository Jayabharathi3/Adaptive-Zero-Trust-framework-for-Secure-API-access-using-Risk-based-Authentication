from enum import Enum
from typing import Any, Dict, Optional
from .models import SecureTransferRequest


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RiskDecision(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    BLOCK = "BLOCK"


def _apply_thresholds(score: int) -> Dict[str, str]:
    if score < 40:
        return {
            "risk_level": RiskLevel.LOW.value,
            "decision": RiskDecision.ALLOW.value,
        }

    if 40 <= score < 75:
        return {
            "risk_level": RiskLevel.MEDIUM.value,
            "decision": RiskDecision.STEP_UP_AUTH.value,
        }

    return {
        "risk_level": RiskLevel.HIGH.value,
        "decision": RiskDecision.BLOCK.value,
    }


def evaluate_transfer_risk(
    transfer: SecureTransferRequest,
    *,
    context: Optional[Dict[str, Any]] = None,
    user: Optional[Dict[str, Any]] = None,
    base_risk: int = 0,
) -> Dict[str, Any]:

    ctx = context or {}

    score = float(base_risk)

    # ---- Context-based dynamic scoring ----
    if ctx.get("new_device"):
        score += 30

    if ctx.get("unknown_ip"):
        score += 25

    if transfer.amount > 20_000:
        score += 35
    elif transfer.amount > 5_000:
        score += 25

    if ctx.get("rapid_requests"):
        score += 25

    if ctx.get("suspicious_user_agent"):
        score += 20

    score = max(0, min(100, int(round(score))))

    thresholds = _apply_thresholds(score)

    result: Dict[str, Any] = {
        "risk_score": score,
        "risk_level": thresholds["risk_level"],
        "decision": thresholds["decision"],
    }

    if user is not None:
        result["user_id"] = user.get("sub") or user.get("user_id")

    return result


def calculate_risk(
    transfer: SecureTransferRequest,
    user: Optional[Dict[str, Any]] = None,
    base_risk: int = 0,
    context: Optional[Dict[str, Any]] = None,
) -> int:

    evaluated = evaluate_transfer_risk(
        transfer=transfer,
        context=context,
        user=user,
        base_risk=base_risk,
    )

    return int(evaluated["risk_score"])