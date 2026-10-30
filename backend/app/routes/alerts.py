"""Security alert query, acknowledgement, and resolution routes for SENTINEL X."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from app.core.auth import get_current_user
from app.core.permissions import UserRole, require_roles
from app.services.alert_service import AlertService
from app.core.security import record_audit_log

router = APIRouter(prefix="/alerts", tags=["Alerts & Incident Response"])


class AlertResponse(BaseModel):
    id: str
    threat_type: str
    severity: str
    description: str
    user_id: str
    event_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    acknowledged: bool
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    resolved: bool
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None
    resolution_notes: Optional[str] = None
    timestamp: str


class AlertUpdateRequest(BaseModel):
    acknowledged: Optional[bool] = None
    resolved: Optional[bool] = None
    notes: Optional[str] = Field(None, max_length=500, description="Resolution notes")


@router.get("", response_model=List[AlertResponse])
async def list_security_alerts(
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    """
    List security alerts. Users only see their personal alerts; Analysts and Admins see all tenant alerts.
    """
    role = current_user.get("role", UserRole.USER.value)
    filter_user_id = None if role in (UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value) else current_user["uid"]

    return AlertService.list_alerts(
        user_id=filter_user_id,
        severity=severity,
        resolved=resolved,
        limit=limit,
    )


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_security_alert(
    alert_id: str,
    body: AlertUpdateRequest,
    current_user: dict = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)),
):
    """
    Acknowledge or resolve an active security alert. Restricted to Security Analysts and Admins.
    """
    try:
        updated = AlertService.update_alert(
            alert_id=alert_id,
            acknowledged=body.acknowledged,
            resolved=body.resolved,
            actor_id=current_user["uid"],
            notes=body.notes,
        )

        await record_audit_log(
            action="ALERT_STATUS_UPDATED",
            user_id=current_user["uid"],
            severity="Medium",
            details={"alert_id": alert_id, "acknowledged": body.acknowledged, "resolved": body.resolved},
        )

        return updated
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' was not found.",
        )
