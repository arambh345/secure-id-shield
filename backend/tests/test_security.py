"""Tests for Cryptography, Rate Limiting, Security Headers, and Input Sanitization."""

from fastapi import status
from app.services.crypto_service import CryptoService


def test_crypto_aes_gcm_roundtrip(client, analyst_headers):
    """Encrypted data can be successfully decrypted with valid keys and authentication tag."""
    secret_text = "CLASSIFIED_SENTINEL_CYBER_INTEL_2026"
    enc_res = client.post(
        "/api/v1/crypto/encrypt",
        headers=analyst_headers,
        json={"plaintext": secret_text, "associated_data": "header_metadata"},
    )
    assert enc_res.status_code == status.HTTP_200_OK
    enc_data = enc_res.json()
    assert enc_data["algorithm"] == "AES-256-GCM"
    assert "versioned_package" in enc_data

    # Decrypt
    dec_res = client.post(
        "/api/v1/crypto/decrypt",
        headers=analyst_headers,
        json={
            "versioned_package": enc_data["versioned_package"],
            "associated_data": "header_metadata",
        },
    )
    assert dec_res.status_code == status.HTTP_200_OK
    assert dec_res.json()["plaintext"] == secret_text
    assert dec_res.json()["verified"] is True


def test_crypto_tampering_detection(client, analyst_headers):
    """Tampering with encrypted package or mismatched associated data fails authentication with 400."""
    secret_text = "AUTHENTICATED_PAYLOAD"
    enc_res = client.post(
        "/api/v1/crypto/encrypt",
        headers=analyst_headers,
        json={"plaintext": secret_text, "associated_data": "correct_metadata"},
    )
    pkg = enc_res.json()["versioned_package"]

    # Attempt decrypt with incorrect associated data
    dec_res = client.post(
        "/api/v1/crypto/decrypt",
        headers=analyst_headers,
        json={"versioned_package": pkg, "associated_data": "corrupted_metadata"},
    )
    assert dec_res.status_code == status.HTTP_400_BAD_REQUEST
    assert "authentication failed" in dec_res.json()["detail"].lower()


def test_crypto_signature_verification(client, analyst_headers):
    """Ed25519 digital signatures are generated and cryptographically verified."""
    priv_key, pub_key = CryptoService.generate_signing_keypair()
    message = "CRITICAL_SYSTEM_SECURITY_EVENT"
    sig = CryptoService.sign_message(message, priv_key)

    verify_res = client.post(
        "/api/v1/crypto/verify",
        headers=analyst_headers,
        json={
            "message": message,
            "signature": sig,
            "public_key": pub_key,
        },
    )
    assert verify_res.status_code == status.HTTP_200_OK
    assert verify_res.json()["signature_valid"] is True
    assert verify_res.json()["overall_valid"] is True


def test_security_headers_present(client):
    """HTTP responses include essential hardened security headers."""
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"


def test_rate_limiting_enforcement(client, user_headers):
    """Client exceeding configured rate limit receives 429 Too Many Requests."""
    from app.core.security import rate_limiter
    # Temporarily set lower limit for testing
    original_limit = rate_limiter.rate_limit
    rate_limiter.rate_limit = 5

    try:
        status_codes = []
        for _ in range(7):
            res = client.get("/api/v1/users/me", headers=user_headers)
            status_codes.append(res.status_code)

        assert status.HTTP_429_TOO_MANY_REQUESTS in status_codes
    finally:
        rate_limiter.rate_limit = original_limit
        rate_limiter.reset()
