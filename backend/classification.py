from typing import Dict, Tuple
from .models import APIAnalysisRequest


def classify_api(req: APIAnalysisRequest) -> Tuple[str, float]:
    """
    Heuristic API classifier.
    Returns (classification_label, confidence).
    """
    endpoint_lower = req.endpoint.lower()
    method_upper = req.method.upper()

    if "transfer" in endpoint_lower or "payment" in endpoint_lower:
        return "financial_transfer", 0.9

    if method_upper == "GET":
        return "read_only", 0.7

    if method_upper in {"POST", "PUT", "PATCH"}:
        return "data_modification", 0.8

    return "unknown", 0.5


def estimate_base_risk(classification: str) -> int:
    """
    Improved baseline risk model.

    Financial APIs are sensitive,
    but not automatically step-up level.
    """
    base_risks: Dict[str, int] = {
        "financial_transfer": 20,     
        "data_modification": 30,
        "read_only": 5,
        "unknown": 25,
    }

    return base_risks.get(classification, 25)