"""Dashboard metrics and security posture aggregation routes for SENTINEL X."""

from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.core.permissions import UserRole, require_roles
from app.firebase import get_firestore_client

router = APIRouter(prefix="/dashboard", tags=["Dashboard & Analytics"])


class DashboardOverviewResponse(BaseModel):
    total_users: int
    active_threats: int
    open_alerts: int
    unacknowledged_alerts: int
    login_events_count: int
    behaviour_events_count: int
    severity_breakdown: Dict[str, int]
    threat_types: Dict[str, int]
    recent_events: List[Dict[str, Any]]
    system_status: str


@router.get("/overview", response_model=DashboardOverviewResponse)
async def get_dashboard_overview(
    current_user: dict = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)),
):
    """
    Retrieve real-time aggregate telemetry from Firestore across users, threats, alerts, and login anomalies.
    Restricted to Security Analysts and Administrators.
    """
    db = get_firestore_client()

    users_count = len(list(db.collection("users").stream()))
    threats_docs = list(db.collection("threats").stream())
    alerts_docs = list(db.collection("alerts").stream())
    logins_docs = list(db.collection("login_events").stream())
    behaviour_docs = list(db.collection("behaviour_logs").stream())

    severity_breakdown = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    threat_types: Dict[str, int] = {}
    open_alerts = 0
    unacknowledged = 0

    for a in alerts_docs:
        d = a.to_dict()
        sev = d.get("severity", "Low")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        tt = d.get("threat_type", "Unknown")
        threat_types[tt] = threat_types.get(tt, 0) + 1
        if not d.get("resolved", False):
            open_alerts += 1
        if not d.get("acknowledged", False):
            unacknowledged += 1

    recent_events = []
    # Collect recent alerts and login anomalies
    for doc in sorted(alerts_docs, key=lambda x: (x.to_dict() or {}).get("timestamp", ""), reverse=True)[:5]:
        ad = doc.to_dict()
        recent_events.append({
            "type": "alert",
            "title": ad.get("threat_type"),
            "description": ad.get("description"),
            "severity": ad.get("severity"),
            "timestamp": ad.get("timestamp"),
        })

    for doc in sorted(logins_docs, key=lambda x: (x.to_dict() or {}).get("timestamp", ""), reverse=True)[:5]:
        ld = doc.to_dict()
        if ld.get("anomaly_score", 0) > 30:
            recent_events.append({
                "type": "login_anomaly",
                "title": f"Login Anomaly ({ld.get('ip_address')})",
                "description": ", ".join(ld.get("anomalies", [])),
                "severity": ld.get("severity"),
                "timestamp": ld.get("timestamp"),
            })

    return {
        "total_users": users_count,
        "active_threats": len(threats_docs),
        "open_alerts": open_alerts,
        "unacknowledged_alerts": unacknowledged,
        "login_events_count": len(logins_docs),
        "behaviour_events_count": len(behaviour_docs),
        "severity_breakdown": severity_breakdown,
        "threat_types": threat_types,
        "recent_events": recent_events,
        "system_status": "OPERATIONAL",
    }
