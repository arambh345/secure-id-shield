"""Firebase Authentication verification and current user context for SENTINEL X."""

from datetime import datetime, timezone
import logging
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.firebase import verify_firebase_token, get_firestore_client
from app.core.permissions import UserRole

logger = logging.getLogger("sentinel.auth")
security_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Dict[str, Any]:
    """
    FastAPI dependency that extracts and verifies the Firebase ID token from Authorization header.
    Synchronizes user document in Firestore and returns trusted server-side user context.
    """
    if credentials is None:
        detail = (
            "Missing Authorization token"
            if request.headers.get("Authorization") is None
            else "Invalid, expired, or revoked authentication token"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        decoded_token = verify_firebase_token(token, check_revoked=True)
    except ValueError as err:
        logger.warning("Authentication failure: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    uid = decoded_token.get("uid")
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is missing user identifier",
            headers={"WWW-Authenticate": "Bearer"},
        )

    db = get_firestore_client()
    users_ref = db.collection("users")
    user_doc = users_ref.document(uid).get()

    now_iso = datetime.now(timezone.utc).isoformat()

    if not user_doc.exists:
        # First-time registration synchronization
        email = decoded_token.get("email", "")
        display_name = decoded_token.get("name") or (email.split("@")[0] if email else "User")
        # Token may declare a mock role in test environment, otherwise default to User
        assigned_role = decoded_token.get("role", UserRole.USER.value)
        if assigned_role not in [r.value for r in UserRole]:
            assigned_role = UserRole.USER.value

        user_data = {
            "uid": uid,
            "email": email,
            "display_name": display_name,
            "role": assigned_role,
            "status": "active",
            "mfa_enabled": False,
            "created_at": now_iso,
            "last_login": now_iso,
            "updated_at": now_iso,
        }
        users_ref.document(uid).set(user_data)
        logger.info("Created synchronized Firestore profile for user: %s (Role: %s)", uid, assigned_role)
    else:
        user_data = user_doc.to_dict()
        # Verify account status
        if user_data.get("status") != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account has been suspended or deactivated",
            )
        # Update last seen timestamp
        users_ref.document(uid).update({"last_login": now_iso})

    # Return server-verified user record
    return user_data
