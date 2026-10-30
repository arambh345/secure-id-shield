"""Identity Impersonation Detection Route for SENTINEL X."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from app.core.permissions import UserRole, require_roles
from app.services.impersonation_service import ImpersonationService
from app.services.alert_service import AlertService
from app.firebase import get_firestore_client

router = APIRouter(prefix="/impersonation", tags=["Identity Impersonation"])


class ImpersonationCheckRequest(BaseModel):
    candidate_name: str = Field(..., min_length=2, max_length=100, description="Name/handle to check")
    candidate_email: Optional[str] = Field(None, max_length=150, description="Email address to check")
    target_identities: Optional[List[Dict[str, str]]] = Field(
        None, description="Optional custom target identities to evaluate against"
    )


class ImpersonationCheckResponse(BaseModel):
    candidate_name: str
    candidate_email: Optional[str] = None
    similarity_score: float
    risk_score: int
    severity: str
    matched_target: Optional[Dict[str, str]] = None
    findings: List[str]
    explanation: str
    checked_at: str


@router.post("/check", response_model=ImpersonationCheckResponse)
async def check_identity_impersonation(
    body: ImpersonationCheckRequest,
    current_user: dict = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)),
):
    """
    Evaluate candidate name/email for homoglyphs, visual similarity, and executive impersonation.
    Authorized for Security Analysts and Administrators.
    """
    result = ImpersonationService.check_identity(
        candidate_name=body.candidate_name,
        candidate_email=body.candidate_email,
        target_identities=body.target_identities,
    )

    if result["risk_score"] >= 60:
        db = get_firestore_client()
        threats_ref = db.collection("threats")
        import uuid
        threat_id = str(uuid.uuid4())
        threat_record = {
            "id": threat_id,
            "threat_type": "Identity Impersonation",
            "candidate_name": body.candidate_name,
            "candidate_email": body.candidate_email,
            "risk_score": result["risk_score"],
            "severity": result["severity"],
            "matched_target": result["matched_target"],
            "findings": result["findings"],
            "analyzed_by": current_user["uid"],
            "timestamp": result["checked_at"],
        }
        threats_ref.document(threat_id).set(threat_record)

        AlertService.create_alert(
            threat_type="Executive Impersonation Attempt",
            severity=result["severity"],
            description=f"Potential impersonation of '{body.candidate_name}' (Risk Score: {result['risk_score']})",
            user_id=current_user["uid"],
            event_id=threat_id,
            metadata=threat_record,
        )

    return result
