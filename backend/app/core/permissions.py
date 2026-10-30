"""Role definitions and Role-Based Access Control (RBAC) permissions for SENTINEL X."""

from enum import Enum
from typing import Callable
from fastapi import HTTPException, status, Depends


class UserRole(str, Enum):
    """Supported roles in SENTINEL X."""
    ADMIN = "Admin"
    SECURITY_ANALYST = "Security Analyst"
    USER = "User"


# Role hierarchy/permission sets
ROLE_PERMISSIONS = {
    UserRole.ADMIN: {
        "manage_users",
        "manage_roles",
        "view_threats",
        "manage_threats",
        "view_alerts",
        "manage_alerts",
        "view_audit_logs",
        "view_dashboard",
        "analyze_phishing",
        "check_impersonation",
        "view_anomalies",
        "view_behaviour_logs",
        "crypto_operations",
    },
    UserRole.SECURITY_ANALYST: {
        "view_threats",
        "view_alerts",
        "manage_alerts",
        "analyze_phishing",
        "check_impersonation",
        "view_anomalies",
        "view_behaviour_logs",
        "crypto_operations",
    },
    UserRole.USER: {
        "view_own_profile",
        "update_own_profile",
        "analyze_phishing",
        "view_own_alerts",
    },
}


def require_roles(*allowed_roles: UserRole) -> Callable:
    """
    FastAPI dependency factory enforcing role authorization.
    Verifies that the authenticated user possesses one of the allowed roles.
    """
    from app.core.auth import get_current_user

    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = current_user.get("role", UserRole.USER.value)
        allowed_role_values = [r.value for r in allowed_roles]

        if user_role not in allowed_role_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Requires one of roles: {', '.join(allowed_role_values)}",
            )
        return current_user

    return role_checker
