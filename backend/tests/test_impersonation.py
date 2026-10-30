"""Tests for Identity Impersonation and homoglyph detection."""

from fastapi import status


def test_impersonation_detection_admin_spoof(client, analyst_headers):
    """Detects visual lookalike of Administrator identity."""
    response = client.post(
        "/api/v1/impersonation/check",
        headers=analyst_headers,
        json={
            "candidate_name": "Adm1n1strat0r",
            "candidate_email": "adm1n@sent1nel.internal",
        },
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["risk_score"] >= 60
    assert data["severity"] in ("High", "Critical")
    assert any("homoglyph" in f.lower() or "lookalike" in f.lower() or "typo" in f.lower() for f in data["findings"])


def test_benign_unique_identity(client, analyst_headers):
    """Unique identity does not trigger impersonation alert."""
    response = client.post(
        "/api/v1/impersonation/check",
        headers=analyst_headers,
        json={"candidate_name": "Samantha Wright", "candidate_email": "swright@partner.org"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["risk_score"] < 30
    assert data["severity"] == "Low"
