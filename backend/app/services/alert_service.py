"""Security Alert Management and Tiered Response Engine for SENTINEL X."""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from app.firebase import get_firestore_client
from app.core.security import record_audit_log


class AlertService:
    """Creates, deduplicates, and manages security alerts and automated responses."""

    @staticmethod
    def create_alert(
        threat_type: str,
        severity: str,
        description: str,
        user_id: Optional[str] = None,
        event_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Dict[str, Any]:
        db = get_firestore_client()
        alerts_ref = db.collection("alerts")
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        # Deduplication check: Do not re-create an open alert for the same threat & user in the last 15 mins
        recent_cutoff = (now - timedelta(minutes=15)).isoformat()
        existing_query = (
            alerts_ref.where("threat_type", "==", threat_type)
            .where("user_id", "==", user_id or "system")
            .where("resolved", "==", False)
            .stream()
        )
        for doc in existing_query:
            data = doc.to_dict()
            if data.get("timestamp", "") > recent_cutoff:
                # Duplicate alert suppressed
                return data

        alert_id = str(uuid.uuid4())
        alert_data = {
            "id": alert_id,
            "threat_type": threat_type,
            "severity": severity,
            "description": description,
            "user_id": user_id or "system",
            "event_id": event_id or alert_id,
            "metadata": metadata or {},
            "acknowledged": False,
            "acknowledged_by": None,
            "acknowledged_at": None,
            "resolved": False,
            "resolved_by": None,
            "resolved_at": None,
            "resolution_notes": None,
            "timestamp": now_iso,
        }

        alerts_ref.document(alert_id).set(alert_data)

        # Tiered Automated Response Execution
        AlertService._execute_tiered_response(alert_data)

        return alert_data

    @staticmethod
    def _execute_tiered_response(alert: dict):
        """Executes safe, proportionate, and reversible defensive actions based on severity tier."""
        severity = alert.get("severity")
        user_id = alert.get("user_id")

        if severity == "Critical":
            # Tier 4: Restrict affected user session and flag for admin investigation
            db = get_firestore_client()
            if user_id and user_id != "system":
                user_doc = db.collection("users").document(user_id)
                if user_doc.get().exists:
                    user_doc.update({"security_hold": True, "hold_reason": alert.get("description")})

            # Record in audit log
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(
                        record_audit_log(
                            action="CRITICAL_TIER_RESPONSE_TRIGGERED",
                            user_id=user_id,
                            severity="Critical",
                            details={"alert_id": alert.get("id"), "threat": alert.get("threat_type")},
                        )
                    )
            except Exception:
                pass

    @staticmethod
    def list_alerts(
        user_id: Optional[str] = None,
        severity: Optional[str] = None,
        resolved: Optional[bool] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List alerts with optional filtering by user, severity, or resolution status."""
        db = get_firestore_client()
        alerts_ref = db.collection("alerts")

        query = alerts_ref.order_by("timestamp", direction="DESCENDING").limit(limit)
        if user_id:
            query = alerts_ref.where("user_id", "==", user_id).limit(limit)

        results = []
        for doc in query.stream():
            data = doc.to_dict()
            if severity and data.get("severity") != severity:
                continue
            if resolved is not None and data.get("resolved") != resolved:
                continue
            results.append(data)
        return results

    @staticmethod
    def update_alert(
        alert_id: str,
        acknowledged: Optional[bool] = None,
        resolved: Optional[bool] = None,
        actor_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Acknowledge or resolve an existing alert with audit tracking."""
        db = get_firestore_client()
        alert_ref = db.collection("alerts").document(alert_id)
        snap = alert_ref.get()

        if not snap.exists:
            raise KeyError(f"Alert '{alert_id}' does not exist")

        now_iso = datetime.now(timezone.utc).isoformat()
        updates = {}

        if acknowledged is not None:
            updates["acknowledged"] = acknowledged
            if acknowledged:
                updates["acknowledged_by"] = actor_id
                updates["acknowledged_at"] = now_iso

        if resolved is not None:
            updates["resolved"] = resolved
            if resolved:
                updates["resolved_by"] = actor_id
                updates["resolved_at"] = now_iso
                if notes:
                    updates["resolution_notes"] = notes

        if updates:
            alert_ref.update(updates)

        return alert_ref.get().to_dict()
