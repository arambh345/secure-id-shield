"""Phishing and URL Threat Detection Route for SENTINEL X."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from app.core.auth import get_current_user
from app.services.phishing_service import PhishingService
from app.services.alert_service import AlertService
from app.firebase import get_firestore_client
from app.core.security import is_safe_url

router = APIRouter(prefix="/phishing", tags=["Phishing & URL Detection"])


class PhishingAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048, description="URL string to analyze")


class PhishingAnalysisResponse(BaseModel):
    url: str
    findings: List[str]
    risk_score: int
    severity: str
    explanation: str
    analyzed_at: str


@router.post("/analyze", response_model=PhishingAnalysisResponse)
async def analyze_phishing_url(
    body: PhishingAnalysisRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Submit a suspicious URL for multi-heuristic phishing, homoglyph, and brand impersonation analysis.
    Available to all authenticated users.
    """
    raw_url = body.url.strip()
    if not is_safe_url(raw_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provided URL is invalid or uses an unsupported/dangerous protocol scheme.",
        )

    result = PhishingService.analyze_url(raw_url)

    # If high risk or critical, store in threats collection and create alert
    if result["risk_score"] >= 60:
        db = get_firestore_client()
        threats_ref = db.collection("threats")
        import uuid
        threat_id = str(uuid.uuid4())
        threat_record = {
            "id": threat_id,
            "threat_type": "Phishing URL",
            "url": raw_url,
            "risk_score": result["risk_score"],
            "severity": result["severity"],
            "findings": result["findings"],
            "submitted_by": current_user["uid"],
            "timestamp": result["analyzed_at"],
        }
        threats_ref.document(threat_id).set(threat_record)

        # Trigger alert
        AlertService.create_alert(
            threat_type="Phishing Threat Detected",
            severity=result["severity"],
            description=f"High-risk phishing URL detected: {raw_url[:60]}... (Score: {result['risk_score']})",
            user_id=current_user["uid"],
            event_id=threat_id,
            metadata=threat_record,
        )

    return result
