"""Tests for Firebase Authentication, token verification, and user profile sync."""

from fastapi import status


def test_missing_auth_token_rejected(client):
    """Protected endpoint must reject requests without Authorization header."""
    response = client.get("/api/v1/users/me")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Not authenticated" in response.text or "Missing" in response.text


def test_invalid_auth_token_rejected(client):
    """Protected endpoint must reject invalid, malformed, or fake tokens."""
    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer totally-invalid-token-12345"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid, expired, or revoked" in response.json()["detail"]


def test_valid_token_user_profile_sync(client, user_headers):
    """Valid token creates and synchronizes user document in Firestore."""
    response = client.get("/api/v1/users/me", headers=user_headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["uid"] == "regular-user"
    assert data["role"] == "User"
    assert data["status"] == "active"


def test_user_can_update_permitted_profile_fields(client, user_headers):
    """Users can update their display_name but cannot change their role or status."""
    # First sync user
    client.get("/api/v1/users/me", headers=user_headers)

    # Update display name
    update_res = client.patch(
        "/api/v1/users/me",
        headers=user_headers,
        json={"display_name": "New Regular Name"},
    )
    assert update_res.status_code == status.HTTP_200_OK
    assert update_res.json()["display_name"] == "New Regular Name"
    # Ensure role is still User
    assert update_res.json()["role"] == "User"


def test_suspended_user_is_forbidden(client, user_headers):
    """Suspended or deactivated user accounts must be rejected with 403 Forbidden."""
    # Create user first
    client.get("/api/v1/users/me", headers=user_headers)

    # Set status to suspended in Firestore
    from app.firebase import get_firestore_client
    db = get_firestore_client()
    db.collection("users").document("regular-user").update({"status": "suspended"})

    response = client.get("/api/v1/users/me", headers=user_headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "suspended" in response.json()["detail"].lower()
