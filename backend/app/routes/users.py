"""User management and profile routes for SENTINEL X."""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, EmailStr
from app.core.auth import get_current_user
from app.core.permissions import UserRole, require_roles
from app.firebase import get_firestore_client
from app.core.security import record_audit_log

router = APIRouter(prefix="/users", tags=["Users & Identity"])


class UserProfileResponse(BaseModel):
    uid: str
    email: str
    display_name: str
    role: str
    status: str
    mfa_enabled: bool = False
    created_at: str
    last_login: Optional[str] = None
    updated_at: Optional[str] = None


class UserProfileUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(None, min_length=2, max_length=50)
    phone_number: Optional[str] = Field(None, max_length=20)


class UserRoleUpdateRequest(BaseModel):
    role: UserRole = Field(..., description="Target role: Admin, Security Analyst, or User")


@router.get("/me", response_model=UserProfileResponse)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    """Retrieve the authenticated user's profile information."""
    return current_user


@router.patch("/me", response_model=UserProfileResponse)
async def update_my_profile(
    body: UserProfileUpdateRequest,
    current_user: dict = Depends(get_current_user),
):
    """Update permitted personal profile fields for the authenticated user."""
    db = get_firestore_client()
    uid = current_user["uid"]
    users_ref = db.collection("users")

    updates = {}
    if body.display_name is not None:
        updates["display_name"] = body.display_name.strip()
    if body.phone_number is not None:
        updates["phone_number"] = body.phone_number.strip()

    if not updates:
        return current_user

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    users_ref.document(uid).update(updates)

    updated_doc = users_ref.document(uid).get().to_dict()
    return updated_doc


@router.get("", response_model=List[UserProfileResponse])
async def list_all_users(
    current_user: dict = Depends(require_roles(UserRole.ADMIN)),
):
    """Admin only: List all registered user profiles."""
    db = get_firestore_client()
    users_ref = db.collection("users")
    user_list = []
    for doc in users_ref.stream():
        user_list.append(doc.to_dict())
    return user_list


@router.patch("/{user_id}/role", response_model=UserProfileResponse)
async def update_user_role(
    user_id: str,
    body: UserRoleUpdateRequest,
    current_user: dict = Depends(require_roles(UserRole.ADMIN)),
):
    """Admin only: Assign a new role to a user. Prevents self-demotion to avoid lockout."""
    if user_id == current_user["uid"] and body.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot demote their own account to prevent system lockout",
        )

    db = get_firestore_client()
    target_ref = db.collection("users").document(user_id)
    target_doc = target_ref.get()

    if not target_doc.exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target_ref.update({
        "role": body.role.value,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })

    await record_audit_log(
        action="USER_ROLE_CHANGED",
        user_id=current_user["uid"],
        severity="High",
        details={"target_user_id": user_id, "new_role": body.role.value},
    )

    return target_ref.get().to_dict()
