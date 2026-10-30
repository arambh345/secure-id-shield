"""Login Anomaly and Behavioral Access Monitoring Service for SENTINEL X."""

from datetime import datetime, timezone
import uuid
from typing import Dict, Any, List, Optional
from app.firebase import get_firestore_client


class LoginAnomalyService:
    """Evaluates login events against user behavioral baselines to detect credential abuse."""

    @staticmethod
    def record_and_evaluate_login(
        user_id: str,
        ip_address: str,
        user_agent: str,
        device_id: Optional[str] = None,
        location: Optional[str] = None,
        login_successful: bool = True,
    ) -> Dict[str, Any]:
        db = get_firestore_client()
        events_ref = db.collection("login_events")
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        current_hour = now.hour

        # Fetch recent historical login events for this user (up to last 30)
        history_query = (
            events_ref.where("user_id", "==", user_id)
            .order_by("timestamp", direction="DESCENDING")
            .limit(30)
        )
        historical_events = [doc.to_dict() for doc in history_query.stream()]

        anomalies: List[str] = []
        anomaly_score = 0

        # 1. Failed attempts analysis (Brute Force / Credential Stuffing detection)
        recent_failed = [
            e for e in historical_events[:10]
            if not e.get("login_successful", True)
        ]
        if not login_successful:
            anomaly_score += 20
            anomalies.append("Failed login attempt recorded")
            if len(recent_failed) >= 3:
                anomaly_score += 45
                anomalies.append(f"Multiple consecutive failed login attempts detected ({len(recent_failed) + 1})")
        elif len(recent_failed) >= 3:
            # Successful login immediately after repeated failures
            anomaly_score += 35
            anomalies.append(f"Successful authentication immediately following {len(recent_failed)} failed attempts")

        # If user has established history, compare baselines
        if historical_events:
            # 2. Device / User-Agent Anomaly
            known_user_agents = {e.get("user_agent") for e in historical_events if e.get("user_agent")}
            known_device_ids = {e.get("device_id") for e in historical_events if e.get("device_id")}

            is_new_device = False
            if device_id and device_id not in known_device_ids:
                is_new_device = True
                anomalies.append(f"Login from previously unseen device hardware ID: {device_id}")
                anomaly_score += 20

            if user_agent and user_agent not in known_user_agents:
                anomalies.append(f"Login from new browser/client user-agent signature")
                anomaly_score += 15

            # 3. Location Anomaly (Only evaluated if reliable location metadata is provided)
            if location:
                known_locations = {e.get("location") for e in historical_events if e.get("location")}
                if known_locations and location not in known_locations:
                    anomalies.append(f"Login from unfamiliar geographic location: {location}")
                    anomaly_score += 25

            # 4. Off-Hours / Unusual Login Time Check
            historical_hours = [
                datetime.fromisoformat(e["timestamp"]).hour
                for e in historical_events
                if "timestamp" in e
            ]
            if len(historical_hours) >= 5:
                min_h, max_h = min(historical_hours), max(historical_hours)
                # If current hour is outside normal operating band and is late night (00:00 - 05:00)
                if (current_hour < min_h or current_hour > max_h) and (0 <= current_hour <= 5):
                    anomalies.append(f"Authentication occurred outside established active hours (Hour: {current_hour}:00 UTC)")
                    anomaly_score += 15

            # 5. Rapid Access Velocity / Frequency Spike
            if historical_events:
                last_event_time_str = historical_events[0].get("timestamp")
                if last_event_time_str:
                    try:
                        last_time = datetime.fromisoformat(last_event_time_str)
                        diff_seconds = (now - last_time).total_seconds()
                        if diff_seconds < 10 and historical_events[0].get("ip_address") != ip_address:
                            anomalies.append(f"Impossible travel / rapid IP shift ({diff_seconds:.1f}s between distinct IPs)")
                            anomaly_score += 50
                    except Exception:
                        pass
        else:
            # First recorded login for this user
            anomalies.append("Initial authentication baseline created for this account")

        # Clamp anomaly score (0-100)
        anomaly_score = min(max(anomaly_score, 0), 100)

        if anomaly_score >= 80:
            severity = "Critical"
        elif anomaly_score >= 60:
            severity = "High"
        elif anomaly_score >= 30:
            severity = "Medium"
        else:
            severity = "Low"

        event_id = str(uuid.uuid4())
        event_record = {
            "id": event_id,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "device_id": device_id or "unknown",
            "location": location or "unspecified",
            "login_successful": login_successful,
            "anomaly_score": anomaly_score,
            "severity": severity,
            "anomalies": anomalies,
            "timestamp": now_iso,
        }

        # Persist event in Firestore
        events_ref.document(event_id).set(event_record)

        return event_record

    @staticmethod
    def get_user_anomalies(user_id: Optional[str] = None, min_severity: str = "Medium") -> List[Dict[str, Any]]:
        """Retrieve recorded anomalies filtered by severity."""
        db = get_firestore_client()
        events_ref = db.collection("login_events")
        severity_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        min_rank = severity_order.get(min_severity, 1)

        query = events_ref.order_by("timestamp", direction="DESCENDING").limit(50)
        if user_id:
            query = events_ref.where("user_id", "==", user_id).limit(50)

        results = []
        for doc in query.stream():
            data = doc.to_dict()
            if severity_order.get(data.get("severity", "Low"), 0) >= min_rank:
                results.append(data)
        return results
