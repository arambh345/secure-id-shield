"""Tests for Risk Scoring Engine and boundary thresholds."""

from fastapi import status


def test_zero_risk_baseline(client, user_headers):
    """Empty risk factors yield baseline healthy score."""
    response = client.post(
        "/api/v1/risk/calculate",
        headers=user_headers,
        json={"source": "Health Check"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["risk_score"] == 0
    assert data["severity"] == "Low"
    assert "Tier 1" in data["recommended_response"]


def test_medium_risk_boundary(client, user_headers):
    """Factors resulting in 30-59 yield Medium severity and Tier 2 response."""
    response = client.post(
        "/api/v1/risk/calculate",
        headers=user_headers,
        json={
            "source": "Network Ingress",
            "phishing_score": 45,
            "login_anomaly_score": 40,
        },
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert 30 <= data["risk_score"] <= 59
    assert data["severity"] == "Medium"
    assert "Tier 2" in data["recommended_response"]


def test_high_risk_boundary(client, user_headers):
    """Factors resulting in 60-79 yield High severity and Tier 3 response."""
    response = client.post(
        "/api/v1/risk/calculate",
        headers=user_headers,
        json={
            "source": "Identity Gateway",
            "impersonation_score": 75,
            "login_anomaly_score": 65,
        },
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert 60 <= data["risk_score"] <= 79
    assert data["severity"] == "High"
    assert "Tier 3" in data["recommended_response"]


def test_critical_risk_boundary(client, user_headers):
    """Factors resulting in 80-100 yield Critical severity and Tier 4 response."""
    response = client.post(
        "/api/v1/risk/calculate",
        headers=user_headers,
        json={
            "source": "EDR Integration",
            "phishing_score": 90,
            "impersonation_score": 85,
            "login_anomaly_score": 90,
        },
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert 80 <= data["risk_score"] <= 100
    assert data["severity"] == "Critical"
    assert "Tier 4" in data["recommended_response"]
    assert len(data["reasons"]) >= 3
