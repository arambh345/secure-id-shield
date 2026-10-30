"""Login events and anomaly monitoring routes for SENTINEL X."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from app.core.auth import get_current_user
from app.core.permissions import UserRole, require_roles
from app.services.anomaly_service import LoginAnomalyService
from app.services.alert_service import AlertService

router = APIRouter(prefix="/login", tags=["Login Anomaly Detection"])


class LoginEventRequest(BaseModel):
    user_id: Optional[str] = Field(None, description="Target user ID (defaults to current authenticated user)")
    device_id: Optional[str] = Field(None, max_length=100, description="Device/hardware identifier")
    location: Optional[str] = Field(None, max_length=100, description="Geographic location string (e.g. City, Country)")
    login_successful: bool = Field(True, description="Whether the authentication attempt succeeded")


class LoginEventResponse(BaseModel):
    id: str
    user_id: str
    ip_address: str
    user_agent: str
    device_id: str
    location: str
    login_successful: bool
    anomaly_score: int
    severity: str
    anomalies: List[str]
    timestamp: str


@router.post("/events", response_model=LoginEventResponse)
async def record_login_event(
    body: LoginEventRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    Record an authentication event and evaluate real-time access anomalies against historical baselines.
    """
    target_user_id = body.user_id if body.user_id else current_user["uid"]

    client_ip = request.client.host if request.client else "127.0.0.1"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    user_agent = request.headers.get("User-Agent", "Unknown Client")

    event_record = LoginAnomalyService.record_and_evaluate_login(
        user_id=target_user_id,
        ip_address=client_ip,
        user_agent=user_agent,
        device_id=body.device_id,
        location=body.location,
        login_successful=body.login_successful,
    )

    if event_record["anomaly_score"] >= 60:
        AlertService.create_alert(
            threat_type="Suspicious Login Anomaly",
            severity=event_record["severity"],
            description=f"Access anomaly detected for user {target_user_id}: {', '.join(event_record['anomalies'][:2])}",
            user_id=target_user_id,
            event_id=event_record["id"],
            metadata=event_record,
        )

    return event_record


@router.get("/anomalies", response_model=List[LoginEventResponse])
async def get_login_anomalies(
    user_id: Optional[str] = None,
    min_severity: str = "Medium",
    current_user: dict = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)),
):
    """
    Security Analyst / Admin: Retrieve recent login anomalies meeting the severity threshold.
    """
    return LoginAnomalyService.get_user_anomalies(user_id=user_id, min_severity=min_severity)
