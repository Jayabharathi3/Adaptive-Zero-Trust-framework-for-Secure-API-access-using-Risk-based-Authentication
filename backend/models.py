from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class APIAnalysisRequest(BaseModel):
    endpoint: str = Field(..., description="Target API endpoint path or URL")
    method: str = Field(..., description="HTTP method, e.g. GET, POST")
    headers: Dict[str, str] = Field(
        default_factory=dict, description="Representative request headers"
    )
    payload: Optional[Dict[str, Any]] = Field(
        default=None, description="Representative JSON payload body"
    )


class APIAnalysisResult(BaseModel):
    request_id: str
    classification: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_score: int = Field(..., ge=0, le=100)


class SecureTransferRequest(BaseModel):
    amount: float = Field(..., gt=0, description="Transfer amount")
    currency: str = Field(..., min_length=3, max_length=3, description="ISO currency")
    source_account: str = Field(..., description="Source account identifier")
    destination_account: str = Field(..., description="Destination account identifier")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary context for risk engine"
    )


class BankingTransferResult(BaseModel):
    transaction_id: str
    status: str
    provider: str = "simulated_banking_api"


class SecureTransferDecision(BaseModel):
    decision: str = Field(..., description="allowed | step_up_required | blocked")
    risk_score: int = Field(..., ge=0, le=100)
    reason: str
    transaction: Optional[BankingTransferResult] = None


class ErrorResponse(BaseModel):
    request_id: Optional[str]
    error: str
    detail: Optional[str] = None

class OpenAPISpecRequest(BaseModel):
    spec: Dict[str, Any] = Field(
        ..., description="Full OpenAPI/Swagger JSON specification"
    )


class OpenAPISecurityResult(BaseModel):
    request_id: str
    https_enabled: bool
    authentication_defined: bool
    admin_exposed: bool
    dangerous_unprotected: bool
    security_score: int
    risk_level: str