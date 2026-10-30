"""Tests for Role-Based Access Control (RBAC) and permission enforcement."""

from fastapi import status


def test_regular_user_cannot_access_user_list(client, user_headers):
    """Regular User role must be forbidden from accessing GET /api/v1/users."""
    response = client.get("/api/v1/users", headers=user_headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Access denied" in response.json()["detail"]


def test_admin_can_access_user_list(client, admin_headers):
    """Administrator role is permitted to access GET /api/v1/users."""
    response = client.get("/api/v1/users", headers=admin_headers)
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


def test_analyst_cannot_update_user_role(client, analyst_headers):
    """Security Analyst role is forbidden from modifying user roles."""
    response = client.patch(
        "/api/v1/users/target-user/role",
        headers=analyst_headers,
        json={"role": "Admin"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_can_update_other_user_role(client, admin_headers, user_headers):
    """Admin can update another user's role in Firestore."""
    # First register user
    client.get("/api/v1/users/me", headers=user_headers)

    response = client.patch(
        "/api/v1/users/regular-user/role",
        headers=admin_headers,
        json={"role": "Security Analyst"},
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["role"] == "Security Analyst"


def test_admin_cannot_demote_self(client, admin_headers):
    """Admin cannot demote their own account to prevent lockout."""
    # Sync admin first
    client.get("/api/v1/users/me", headers=admin_headers)

    response = client.patch(
        "/api/v1/users/admin-user/role",
        headers=admin_headers,
        json={"role": "User"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "lockout" in response.json()["detail"].lower()
