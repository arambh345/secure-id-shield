"""Transparent and Weighted Risk Scoring Engine for SENTINEL X."""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class RiskScoringService:
    """Calculates multidimensional cyber risk scores based on weighted security signals."""

    WEIGHTS = {
        "phishing_findings": 0.35,
        "impersonation_score": 0.25,
        "login_anomalies": 0.25,
        "behaviour_anomalies": 0.15,
    }

    @staticmethod
    def calculate_risk(
        source: str,
        phishing_score: Optional[int] = None,
        impersonation_score: Optional[int] = None,
        login_anomaly_score: Optional[int] = None,
        behaviour_score: Optional[int] = None,
        context_factors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Computes composite risk score from 0 to 100 with contributing reasons and recommended actions.
        """
        reasons: List[str] = []
        active_weights = {}
        sub_scores = {}

        if phishing_score is not None:
            active_weights["phishing"] = 0.35
            sub_scores["phishing"] = min(max(phishing_score, 0), 100)
            if phishing_score > 30:
                reasons.append(f"Phishing analysis contributed risk weight: score {phishing_score}/100")

        if impersonation_score is not None:
            active_weights["impersonation"] = 0.30
            sub_scores["impersonation"] = min(max(impersonation_score, 0), 100)
            if impersonation_score > 30:
                reasons.append(f"Identity impersonation indicators contributed risk weight: score {impersonation_score}/100")

        if login_anomaly_score is not None:
            active_weights["login"] = 0.25
            sub_scores["login"] = min(max(login_anomaly_score, 0), 100)
            if login_anomaly_score > 30:
                reasons.append(f"Authentication anomalies contributed risk weight: score {login_anomaly_score}/100")

        if behaviour_score is not None:
            active_weights["behaviour"] = 0.20
            sub_scores["behaviour"] = min(max(behaviour_score, 0), 100)
            if behaviour_score > 30:
                reasons.append(f"Unusual account behaviour contributed risk weight: score {behaviour_score}/100")

        # If only a single factor was submitted, use that factor directly
        if len(sub_scores) == 1:
            risk_score = list(sub_scores.values())[0]
        elif sub_scores:
            # Weighted normalization
            total_weight = sum(active_weights.values())
            weighted_sum = sum(sub_scores[k] * (active_weights[k] / total_weight) for k in sub_scores)
            risk_score = int(round(weighted_sum))
        else:
            risk_score = 0
            reasons.append("No adverse security signals observed.")

        # Additional context factor adjustments
        if context_factors:
            for factor in context_factors:
                reasons.append(f"Contextual factor observed: {factor}")
                risk_score = min(risk_score + 5, 100)

        # Severity categorization based on configured thresholds
        # 0–29: Low, 30–59: Medium, 60–79: High, 80–100: Critical
        if risk_score >= 80:
            severity = "Critical"
            recommended_response = (
                "Tier 4: Restrict affected session, alert Security Admin, require offline identity verification."
            )
        elif risk_score >= 60:
            severity = "High"
            recommended_response = (
                "Tier 3: Challenge user with step-up multi-factor authentication (MFA) and notify Security Analyst."
            )
        elif risk_score >= 30:
            severity = "Medium"
            recommended_response = (
                "Tier 2: Generate an internal security alert and prompt user to review recent account access."
            )
        else:
            severity = "Low"
            recommended_response = "Tier 1: Record event in security audit log. No restrictive user disruption needed."

        return {
            "risk_score": risk_score,
            "severity": severity,
            "reasons": reasons if reasons else ["Baseline security profile is healthy"],
            "detection_source": source or "SENTINEL Risk Engine",
            "recommended_response": recommended_response,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
