from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests

DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH"}
ADMIN_KEYWORDS = {"admin", "internal", "root", "manage"}


# ----------------------------
# HTTPS CHECK (UPGRADED)
# ----------------------------
def _uses_https(servers: List[Dict[str, Any]], source_url: Optional[str] = None) -> bool:
    """
    Check if HTTPS is used either:
    1️⃣ In OpenAPI servers section
    2️⃣ In the source URL used to fetch the spec
    """
    # 1️⃣ Check servers inside spec
    for server in servers:
        url = server.get("url", "")
        if url:
            parsed = urlparse(url)
            if parsed.scheme.lower() == "https":
                return True

    # 2️⃣ Fallback: Check source URL
    if source_url:
        parsed = urlparse(source_url)
        if parsed.scheme.lower() == "https":
            return True

    return False


# ----------------------------
# FETCH SPEC FROM LIVE URL
# ----------------------------
def fetch_openapi_from_url(url: str):

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise Exception("Invalid URL scheme. Only HTTP/HTTPS allowed.")

    if parsed.hostname in ["localhost", "127.0.0.1"]:
        raise Exception("Localhost URLs are not allowed.")

    try:
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            raise Exception("Unable to fetch API specification.")

        return response.json()

    except Exception as e:
        raise Exception(f"Failed to fetch OpenAPI spec: {str(e)}")


# ----------------------------
# AUTH CHECK
# ----------------------------
def _has_authentication(spec: Dict[str, Any]) -> bool:
    """
    Detect authentication from:
    - components.securitySchemes
    - global security
    - security defined per path
    """

    components = spec.get("components", {})
    global_security = spec.get("security", [])
    paths = spec.get("paths", {})

    # 1️⃣ Check components.securitySchemes
    if components.get("securitySchemes"):
        return True

    # 2️⃣ Check global security
    if global_security:
        return True

    # 3️⃣ Check path-level security
    for path_data in paths.values():
        for method_data in path_data.values():
            if isinstance(method_data, dict) and method_data.get("security"):
                return True

    return False


# ----------------------------
# PATH ANALYSIS
# ----------------------------
def _is_admin_path(path: str) -> bool:
    lower_path = path.lower()
    return any(keyword in lower_path for keyword in ADMIN_KEYWORDS)


def _analyze_paths(
    paths: Dict[str, Any],
    has_global_security: bool,
) -> Dict[str, Any]:
    admin_exposed = False
    dangerous_unprotected = False

    for path, methods in paths.items():
        if _is_admin_path(path):
            admin_exposed = True

        for method, details in methods.items():
            method_upper = method.upper()

            if method_upper in DANGEROUS_METHODS:
                method_security = details.get("security")
                if not method_security and not has_global_security:
                    dangerous_unprotected = True

    return {
        "admin_exposed": admin_exposed,
        "dangerous_unprotected": dangerous_unprotected,
    }


# ----------------------------
# MAIN ANALYZER (FINAL CLEAN VERSION)
# ----------------------------
def analyze_openapi_spec(
    spec: Dict[str, Any],
    source_url: Optional[str] = None
) -> Dict[str, Any]:

    # ----------------------------
    # 1️⃣ Validate Spec Structure
    # ----------------------------
    if not spec.get("openapi") and not spec.get("swagger"):
        return {
            "https_enabled": False,
            "authentication_defined": False,
            "admin_exposed": False,
            "dangerous_unprotected": False,
            "security_score": 0,
            "risk_level": "INVALID_SPEC",
            "owasp_findings": [],
            "explanations": ["Invalid OpenAPI/Swagger specification."]
        }

    servers = spec.get("servers", [])
    components = spec.get("components", {})
    paths = spec.get("paths", {})
    global_security = spec.get("security", [])

    # ----------------------------
    # 2️⃣ Core Security Checks
    # ----------------------------
    https_enabled = _uses_https(servers, source_url)
    authentication_defined = _has_authentication(spec)
    has_global_security = len(global_security) > 0

    path_analysis = _analyze_paths(paths, has_global_security)

    admin_exposed = path_analysis["admin_exposed"]
    dangerous_unprotected = path_analysis["dangerous_unprotected"]

    # ----------------------------
    # 3️⃣ OWASP-Based Risk Evaluation
    # ----------------------------
    score = 100
    owasp_findings = []
    explanations = []

    # API8 – Security Misconfiguration
    if not https_enabled:
        score -= 20
        owasp_findings.append("API8: Security Misconfiguration")
        explanations.append("API does not enforce HTTPS transport encryption.")

    # API2 – Broken Authentication
    if not authentication_defined:
        score -= 20
        owasp_findings.append("API2: Broken Authentication")
        explanations.append("No authentication mechanisms defined in OpenAPI spec.")

    # API5 – Broken Function Level Authorization
    if dangerous_unprotected:
        score -= 25
        owasp_findings.append("API5: Broken Function Level Authorization")
        explanations.append("Dangerous HTTP methods exposed without security protection.")

    # API9 – Improper Assets Management
    if admin_exposed:
        score -= 20
        owasp_findings.append("API9: Improper Assets Management")
        explanations.append("Administrative/internal endpoints are publicly exposed.")

    # API4 – Unrestricted Resource Consumption (heuristic)
    if "x-ratelimit" not in str(spec).lower():
        score -= 10
        owasp_findings.append("API4: Unrestricted Resource Consumption")
        explanations.append("No rate limiting policy detected in specification.")

    # Large Attack Surface Heuristic
    if len(paths) > 25:
        score -= 10
        owasp_findings.append("API9: Improper Assets Management")
        explanations.append("Large attack surface detected (many exposed endpoints).")

    score = max(0, min(100, score))

    # ----------------------------
    # 4️⃣ Risk Classification
    # ----------------------------
    if score >= 75:
        risk_level = "TRUSTED"
    elif 50 <= score < 75:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "MALICIOUS"

    return {
        "https_enabled": https_enabled,
        "authentication_defined": authentication_defined,
        "admin_exposed": admin_exposed,
        "dangerous_unprotected": dangerous_unprotected,
        "security_score": score,
        "risk_level": risk_level,
        "owasp_findings": owasp_findings,
        "explanations": explanations
    }