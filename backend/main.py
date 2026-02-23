import logging
import sys
import uuid
from typing import Any, Dict, Optional

from dotenv import load_dotenv
import os

load_dotenv()
print("JWT SECRET LOADED:", os.getenv("JWT_SECRET_KEY"))

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


from .openapi_analyzer import analyze_openapi_spec
from .models import OpenAPISpecRequest, OpenAPISecurityResult

from . import auth, classification, risk_engine
from .models import (
    APIAnalysisRequest,
    APIAnalysisResult,
    BankingTransferResult,
    ErrorResponse,
    SecureTransferDecision,
    SecureTransferRequest,
)
from simulated_api.banking_api import process_transfer



class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        base: Dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        extra = {
            "request_id": getattr(record, "request_id", None),
            "path": getattr(record, "path", None),
            "method": getattr(record, "method", None),
            "status_code": getattr(record, "status_code", None),
        }
        for key, value in extra.items():
            if value is not None:
                base[key] = value

        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)

        import json

        return json.dumps(base, ensure_ascii=False)


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = [handler]


configure_logging()
logger = logging.getLogger("zt_gateway")


app = FastAPI(title="Zero-Trust Security Gateway", version="1.0.0")

security = HTTPBearer()

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id

    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "Unhandled error",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
            },
        )
        raise

    response.headers["X-Request-ID"] = request_id
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_request_id(request: Request) -> Optional[str]:
    return getattr(request.state, "request_id", None)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    request_id = get_request_id(request)
    logger.warning(
        "Validation error",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
        },
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            request_id=request_id,
            error="validation_error",
            detail=str(exc),
        ).dict(),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    request_id = get_request_id(request)
    logger.exception(
        "Unhandled server error",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
        },
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            request_id=request_id,
            error="internal_server_error",
            detail="An unexpected error occurred.",
        ).dict(),
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request_id: Optional[str] = Depends(get_request_id),
) -> Dict[str, Any]:

    token = credentials.credentials
    user = auth.verify_token(token)

    logger.info(
        "JWT validated",
        extra={
            "request_id": request_id,
        },
    )

    return user


@app.post(
    "/analyze-openapi",
    response_model=OpenAPISecurityResult,
    summary="Analyze OpenAPI specification security posture",
)

async def analyze_openapi(
    payload: OpenAPISpecRequest,
    request: Request,
) -> OpenAPISecurityResult:
    request_id = get_request_id(request) or str(uuid.uuid4())

    result = analyze_openapi_spec(payload.spec)

    from . import database

    database.log_api_analysis({
        "request_id": request_id,
        "security_score": result["security_score"],
        "risk_level": result["risk_level"]
    })

    logger.info(
        "OpenAPI security analyzed",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
        },
    )

    return OpenAPISecurityResult(
        request_id=request_id,
        https_enabled=result["https_enabled"],
        authentication_defined=result["authentication_defined"],
        admin_exposed=result["admin_exposed"],
        dangerous_unprotected=result["dangerous_unprotected"],
        security_score=result["security_score"],
        risk_level=result["risk_level"],
    )

from pydantic import BaseModel

class LiveAPIRequest(BaseModel):
    url: str


@app.post("/analyze-live-api")
async def analyze_live_api(payload: LiveAPIRequest, request: Request):

    request_id = get_request_id(request) or str(uuid.uuid4())

    from .openapi_analyzer import fetch_openapi_from_url

    try:
        spec = fetch_openapi_from_url(payload.url)

        result = analyze_openapi_spec(spec, payload.url)

        return {
            "request_id": request_id,
            "url": payload.url,
            "security_score": result["security_score"],
            "risk_level": result["risk_level"],
            "https_enabled": result["https_enabled"],
            "authentication_defined": result["authentication_defined"],
            "explanations": result.get("explanations", []),
            "owasp_findings": result.get("owasp_findings", [])
        }

    except Exception as e:
        return {
            "request_id": request_id,
            "url": payload.url,
            "security_score": 0,
            "risk_level": "BLOCKED",
            "https_enabled": False,
            "authentication_defined": False,
            "owasp_findings": ["Invalid or unreachable OpenAPI specification"],
            "explanations": [str(e)]
        }


@app.post(
    "/secure-transfer",
    response_model=SecureTransferDecision,
    summary="Zero-trust secured transfer",
)
async def secure_transfer(
    transfer: SecureTransferRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SecureTransferDecision:
    request_id = get_request_id(request) or str(uuid.uuid4())

    analysis_req = APIAnalysisRequest(
        endpoint="/secure-transfer",
        method="POST",
        headers={},
        payload=transfer.dict(),
    )
    classification_label, _ = classification.classify_api(analysis_req)
    base_risk = classification.estimate_base_risk(classification_label)

    risk_score = risk_engine.calculate_risk(
    transfer=transfer,
    user=current_user,
    base_risk=base_risk,
    context=transfer.metadata
    )
    from . import database

    decision = (
        "allowed" if risk_score < 40
        else "step_up" if 40 <= risk_score <= 70
        else "blocked"
    )

    database.log_security_event({
        "request_id": request_id,
        "user": current_user.get("sub"),
        "risk_score": risk_score,
        "decision": decision
    })

    logger.info(
        "Risk calculated",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
        },
    )

    if risk_score < 40:
        downstream_result_raw = process_transfer(transfer.dict())
        transaction = BankingTransferResult(**downstream_result_raw)

        database.log_transfer_event({
            "request_id": request_id,
            "user": current_user.get("sub"),
            "amount": transfer.amount,
            "source": transfer.source_account,
            "destination": transfer.destination_account
        })

        return SecureTransferDecision(
            decision="allowed",
            risk_score=risk_score,
            reason="Risk score below threshold; transfer forwarded.",
            transaction=transaction,
        )

    elif 40 <= risk_score <= 70:
        return SecureTransferDecision(
            decision="step_up_required",
            risk_score=risk_score,
            reason="Risk score requires step-up authentication (e.g., OTP, WebAuthn).",
        )

    else:
        return SecureTransferDecision(
            decision="blocked",
            risk_score=risk_score,
            reason="Risk score too high; transfer blocked by zero-trust policy.",
        )


@app.get("/health", summary="Health check")
async def health() -> Dict[str, str]:
    return {"status": "ok"}

@app.get("/security-dashboard")
async def security_dashboard():
    from . import database

    security = database.get_security_events()
    api_events = database.get_api_analysis_events()
    transfers = database.get_transfer_events()

    return {
        "total_api_analyses": len(api_events),
        "total_requests": len(security),
        "allowed": len([e for e in security if e["decision"] == "allowed"]),
        "blocked": len([e for e in security if e["decision"] == "blocked"]),
        "step_up": len([e for e in security if e["decision"] == "step_up"]),
        "total_transfers": len(transfers),
        "average_risk_score": (
            sum(e["risk_score"] for e in security) / len(security)
            if security else 0
        )
    }

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Serve static files (CSS, JS)
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# Serve main UI
@app.get("/")
async def serve_index():
    return FileResponse("frontend/index.html")

# Optional dashboard page
@app.get("/dashboard-ui")
async def serve_dashboard():
    return FileResponse("frontend/dashboard.html")

