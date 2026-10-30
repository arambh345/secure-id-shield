"""Behavior monitoring and security telemetry routes for SENTINEL X."""

from datetime import datetime, timezone
import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from app.core.auth import get_current_user
from app.core.permissions import UserRole, require_roles
from app.firebase import get_firestore_client
from app.services.alert_service import AlertService

router = APIRouter(prefix="/behaviour", tags=["Behavior Monitoring"])


class BehaviourEventRequest(BaseModel):
    action: str = Field(..., min_length=2, max_length=100, description="Behavior action (e.g. SENSITIVE_FILE_ACCESS, PROFILE_UPDATE)")
    resource: Optional[str] = Field(None, max_length=200, description="Resource accessed or target entity")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional contextual metadata")
    risk_level: str = Field("Low", description="Assessed risk level: Low, Medium, High, Critical")


class BehaviourEventResponse(BaseModel):
    id: str
    user_id: str
    action: str
    resource: Optional[str] = None
    metadata: Dict[str, Any]
    risk_level: str
    timestamp: str


@router.post("/events", response_model=BehaviourEventResponse)
async def record_behaviour_event(
    body: BehaviourEventRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Log a security-relevant behavioral activity (e.g. sensitive document access, rapid queries).
    """
    db = get_firestore_client()
    logs_ref = db.collection("behaviour_logs")
    event_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    event_record = {
        "id": event_id,
        "user_id": current_user["uid"],
        "action": body.action,
        "resource": body.resource,
        "metadata": body.metadata or {},
        "risk_level": body.risk_level,
        "timestamp": now_iso,
    }

    logs_ref.document(event_id).set(event_record)

    if body.risk_level in ("High", "Critical"):
        AlertService.create_alert(
            threat_type="High-Risk Behavior Event",
            severity=body.risk_level,
            description=f"User {current_user['uid']} triggered sensitive action '{body.action}'",
            user_id=current_user["uid"],
            event_id=event_id,
            metadata=event_record,
        )

    return event_record


@router.get("/logs", response_model=List[BehaviourEventResponse])
async def get_behaviour_logs(
    user_id: Optional[str] = None,
    limit: int = 50,
    current_user: dict = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)),
):
    """
    Security Analyst / Admin: Review recorded user behavioral logs.
    """
    db = get_firestore_client()
    logs_ref = db.collection("behaviour_logs")

    query = logs_ref.order_by("timestamp", direction="DESCENDING").limit(limit)
    if user_id:
        query = logs_ref.where("user_id", "==", user_id).limit(limit)

    results = []
    for doc in query.stream():
        results.append(doc.to_dict())
    return results
