"""Tests for Alerts lifecycle, audit logging, and Dashboard aggregation."""

from fastapi import status


def test_alert_lifecycle_and_resolution(client, admin_headers, analyst_headers):
    """Create alert via high-risk threat, acknowledge, and resolve."""
    # Submit high-risk phishing to generate an alert
    client.post(
        "/api/v1/phishing/analyze",
        headers=analyst_headers,
        json={"url": "http://192.168.1.1/paypa1-login/verify"},
    )

    # List alerts
    list_res = client.get("/api/v1/alerts", headers=analyst_headers)
    assert list_res.status_code == status.HTTP_200_OK
    alerts = list_res.json()
    assert len(alerts) >= 1
    target_alert = alerts[0]
    alert_id = target_alert["id"]

    # Acknowledge alert
    ack_res = client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers=analyst_headers,
        json={"acknowledged": True},
    )
    assert ack_res.status_code == status.HTTP_200_OK
    assert ack_res.json()["acknowledged"] is True
    assert ack_res.json()["acknowledged_by"] == "analyst-user"

    # Resolve alert
    res_res = client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers=admin_headers,
        json={"resolved": True, "notes": "Identified as malicious campaign. Blocked on edge firewall."},
    )
    assert res_res.status_code == status.HTTP_200_OK
    assert res_res.json()["resolved"] is True
    assert res_res.json()["resolution_notes"] is not None


def test_dashboard_overview_aggregation(client, admin_headers, user_headers):
    """Dashboard retrieves accurate aggregate security posture metrics."""
    # Ensure user is registered
    client.get("/api/v1/users/me", headers=user_headers)

    res = client.get("/api/v1/dashboard/overview", headers=admin_headers)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["total_users"] >= 1
    assert data["system_status"] == "OPERATIONAL"
    assert "severity_breakdown" in data
    assert "threat_types" in data
