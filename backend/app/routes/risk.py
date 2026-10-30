"""Risk scoring calculation route for SENTINEL X."""

from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.core.auth import get_current_user
from app.services.risk_service import RiskScoringService

router = APIRouter(prefix="/risk", tags=["Risk Scoring Engine"])


class RiskCalculationRequest(BaseModel):
    source: Optional[str] = Field("API Request", description="Source triggering risk assessment")
    phishing_score: Optional[int] = Field(None, ge=0, le=100, description="Phishing score (0-100)")
    impersonation_score: Optional[int] = Field(None, ge=0, le=100, description="Impersonation score (0-100)")
    login_anomaly_score: Optional[int] = Field(None, ge=0, le=100, description="Login anomaly score (0-100)")
    behaviour_score: Optional[int] = Field(None, ge=0, le=100, description="Behavior anomaly score (0-100)")
    context_factors: Optional[List[str]] = Field(None, description="Qualitative environmental indicators")


class RiskCalculationResponse(BaseModel):
    risk_score: int
    severity: str
    reasons: List[str]
    detection_source: str
    recommended_response: str
    timestamp: str


@router.post("/calculate", response_model=RiskCalculationResponse)
async def calculate_composite_risk(
    body: RiskCalculationRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Transparently compute a unified risk score across weighted security domains with recommended defensive responses.
    """
    return RiskScoringService.calculate_risk(
        source=body.source or "SENTINEL Risk Engine",
        phishing_score=body.phishing_score,
        impersonation_score=body.impersonation_score,
        login_anomaly_score=body.login_anomaly_score,
        behaviour_score=body.behaviour_score,
        context_factors=body.context_factors,
    )
