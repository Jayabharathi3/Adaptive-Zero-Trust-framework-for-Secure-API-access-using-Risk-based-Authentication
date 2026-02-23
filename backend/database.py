from typing import List, Dict, Any
from datetime import datetime

security_events: List[Dict[str, Any]] = []
api_analysis_events: List[Dict[str, Any]] = []
transfer_events: List[Dict[str, Any]] = []


def log_security_event(event: Dict[str, Any]) -> None:
    event["timestamp"] = datetime.utcnow().isoformat()
    security_events.append(event)


def log_api_analysis(event: Dict[str, Any]) -> None:
    event["timestamp"] = datetime.utcnow().isoformat()
    api_analysis_events.append(event)


def log_transfer_event(event: Dict[str, Any]) -> None:
    event["timestamp"] = datetime.utcnow().isoformat()
    transfer_events.append(event)


def get_security_events() -> List[Dict[str, Any]]:
    return security_events


def get_api_analysis_events() -> List[Dict[str, Any]]:
    return api_analysis_events


def get_transfer_events() -> List[Dict[str, Any]]:
    return transfer_events