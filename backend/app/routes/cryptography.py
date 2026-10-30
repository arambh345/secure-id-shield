"""Cryptographic operations routes for SENTINEL X."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from app.core.permissions import UserRole, require_roles
from app.services.crypto_service import CryptoService

router = APIRouter(prefix="/crypto", tags=["Cryptography Module"])


class EncryptRequest(BaseModel):
    plaintext: str = Field(..., min_length=1, description="Data to encrypt with AES-256-GCM")
    associated_data: Optional[str] = Field("", description="Optional authenticated associated data (AAD)")


class EncryptResponse(BaseModel):
    algorithm: str
    version: str
    versioned_package: str
    nonce: str
    ciphertext: str
    tag: str
    has_associated_data: bool


class DecryptRequest(BaseModel):
    versioned_package: str = Field(..., description="Encrypted versioned package (v1:nonce:payload)")
    associated_data: Optional[str] = Field("", description="Optional associated data expected to match")


class DecryptResponse(BaseModel):
    plaintext: str
    verified: bool


class VerifyRequest(BaseModel):
    message: str = Field(..., description="Original message text")
    hash_sha256: Optional[str] = Field(None, description="Expected SHA-256 hex digest for integrity check")
    signature: Optional[str] = Field(None, description="Base64 Ed25519 signature to verify")
    public_key: Optional[str] = Field(None, description="Base64 Ed25519 public key")


class VerifyResponse(BaseModel):
    computed_sha256: str
    hash_match: Optional[bool] = None
    signature_valid: Optional[bool] = None
    overall_valid: bool


@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_payload(
    body: EncryptRequest,
    current_user: dict = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)),
):
    """
    Encrypt sensitive cyber telemetry or credentials using authenticated AES-256-GCM with versioned metadata.
    """
    try:
        return CryptoService.encrypt_data(body.plaintext, body.associated_data or "")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption operation failed: {str(exc)}",
        )


@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt_payload(
    body: DecryptRequest,
    current_user: dict = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)),
):
    """
    Decrypt an AES-256-GCM package. Enforces tag verification; fails with 400 on data tampering.
    """
    try:
        decrypted_text = CryptoService.decrypt_data(body.versioned_package, body.associated_data or "")
        return {"plaintext": decrypted_text, "verified": True}
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )


@router.post("/verify", response_model=VerifyResponse)
async def verify_integrity_or_signature(
    body: VerifyRequest,
    current_user: dict = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)),
):
    """
    Verify message integrity via SHA-256 cryptographic digest and/or Ed25519 digital signature.
    """
    computed_hash = CryptoService.hash_sha256(body.message)
    hash_match = None
    sig_valid = None

    if body.hash_sha256:
        hash_match = (computed_hash.lower() == body.hash_sha256.lower().strip())

    if body.signature and body.public_key:
        sig_valid = CryptoService.verify_signature(body.message, body.signature, body.public_key)

    overall = True
    if hash_match is not None and not hash_match:
        overall = False
    if sig_valid is not None and not sig_valid:
        overall = False

    return {
        "computed_sha256": computed_hash,
        "hash_match": hash_match,
        "signature_valid": sig_valid,
        "overall_valid": overall,
    }
