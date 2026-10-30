"""Tests for Phishing and URL threat detection analysis."""

from fastapi import status


def test_benign_url_analysis(client, user_headers):
    """Legitimate standard URL returns a low risk score."""
    response = client.post(
        "/api/v1/phishing/analyze",
        headers=user_headers,
        json={"url": "https://sentinel-x.io/docs/about"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["risk_score"] < 30
    assert data["severity"] == "Low"
    assert "url" in data
    assert len(data["findings"]) > 0


def test_ip_address_host_detection(client, user_headers):
    """Raw IP address in host is flagged with heightened risk."""
    response = client.post(
        "/api/v1/phishing/analyze",
        headers=user_headers,
        json={"url": "http://192.168.1.100/account/login"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert any("IP address" in f for f in data["findings"])
    assert data["risk_score"] >= 40


def test_lookalike_brand_domain_detection(client, user_headers):
    """Typosquatting / lookalike domain is detected with high risk."""
    response = client.post(
        "/api/v1/phishing/analyze",
        headers=user_headers,
        json={"url": "http://paypa1-security-verification.com/login"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["risk_score"] >= 60
    assert data["severity"] in ("High", "Critical")


def test_punycode_homograph_attack_detected(client, user_headers):
    """Punycode or Cyrillic homoglyph domain is detected."""
    response = client.post(
        "/api/v1/phishing/analyze",
        headers=user_headers,
        json={"url": "https://xn--gogle-pra.com/signin"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert any("Punycode" in f or "homograph" in f.lower() for f in data["findings"])
    assert data["risk_score"] >= 60


def test_dangerous_protocol_scheme_rejected(client, user_headers):
    """Dangerous schemes like javascript: or data: must be rejected with 400 Bad Request."""
    response = client.post(
        "/api/v1/phishing/analyze",
        headers=user_headers,
        json={"url": "javascript:alert(document.cookie)"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid or uses an unsupported" in response.json()["detail"].lower()
