"""Cryptographic operations service using Python's genuine 'cryptography' library."""

import os
import base64
import secrets
import hashlib
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.config import settings


class CryptoService:
    """Provides authenticated AES-256-GCM encryption, SHA-256 hashing, and Ed25519 digital signatures."""

    VERSION = "v1"

    @staticmethod
    def get_master_key() -> bytes:
        """Decode the configured base64 master 32-byte key."""
        key_b64 = settings.SENTINEL_MASTER_KEY
        try:
            key_bytes = base64.b64decode(key_b64)
            if len(key_bytes) != 32:
                raise ValueError("Master key must be exactly 32 bytes (256 bits)")
            return key_bytes
        except Exception as err:
            raise ValueError(f"Invalid SENTINEL_MASTER_KEY configuration: {err}")

    @staticmethod
    def generate_key() -> str:
        """Generate a cryptographically secure 256-bit random key (Base64-encoded)."""
        key = secrets.token_bytes(32)
        return base64.b64encode(key).decode("utf-8")

    @classmethod
    def encrypt_data(cls, plaintext: str, associated_data: str = "") -> Dict[str, Any]:
        """
        Encrypts plaintext string using AES-256-GCM.
        Returns ciphertext, 12-byte random IV/nonce, authentication tag, and versioned package.
        """
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext must be a string")

        key = cls.get_master_key()
        aesgcm = AESGCM(key)

        # 96-bit (12 bytes) recommended nonce for AES-GCM
        nonce = secrets.token_bytes(12)
        pt_bytes = plaintext.encode("utf-8")
        ad_bytes = associated_data.encode("utf-8") if associated_data else None

        # AESGCM.encrypt appends 16-byte authentication tag to ciphertext
        encrypted = aesgcm.encrypt(nonce, pt_bytes, ad_bytes)

        # Separate tag (last 16 bytes) and ciphertext
        ciphertext_bytes = encrypted[:-16]
        tag_bytes = encrypted[-16:]

        nonce_b64 = base64.b64encode(nonce).decode("utf-8")
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("utf-8")
        tag_b64 = base64.b64encode(tag_bytes).decode("utf-8")
        full_payload_b64 = base64.b64encode(encrypted).decode("utf-8")

        # Versioned format package: v1:{nonce_b64}:{full_payload_b64}
        versioned_package = f"{cls.VERSION}:{nonce_b64}:{full_payload_b64}"

        return {
            "algorithm": "AES-256-GCM",
            "version": cls.VERSION,
            "versioned_package": versioned_package,
            "nonce": nonce_b64,
            "ciphertext": ciphertext_b64,
            "tag": tag_b64,
            "has_associated_data": bool(associated_data),
        }

    @classmethod
    def decrypt_data(cls, versioned_package: str, associated_data: str = "") -> str:
        """
        Decrypts an AES-256-GCM versioned package with authentication tag verification.
        Raises ValueError if tampering or tag mismatch is detected.
        """
        parts = versioned_package.split(":")
        if len(parts) != 3:
            raise ValueError("Malformed encrypted package format. Expected 'version:nonce:payload'")

        version, nonce_b64, payload_b64 = parts
        if version != cls.VERSION:
            raise ValueError(f"Unsupported encryption format version: '{version}'")

        try:
            nonce = base64.b64decode(nonce_b64)
            payload = base64.b64decode(payload_b64)
        except Exception:
            raise ValueError("Failed to base64-decode encrypted package components")

        key = cls.get_master_key()
        aesgcm = AESGCM(key)
        ad_bytes = associated_data.encode("utf-8") if associated_data else None

        try:
            decrypted_bytes = aesgcm.decrypt(nonce, payload, ad_bytes)
            return decrypted_bytes.decode("utf-8")
        except Exception:
            raise ValueError("Cryptographic authentication failed. Data may have been tampered with or corrupted.")

    @staticmethod
    def hash_sha256(data: str) -> str:
        """Computes SHA-256 cryptographic digest of data string."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def generate_signing_keypair() -> Tuple[str, str]:
        """Generate Ed25519 digital signature private and public key pair (Base64)."""
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()

        priv_b64 = base64.b64encode(priv_key.private_bytes_raw()).decode("utf-8")
        pub_b64 = base64.b64encode(pub_key.public_bytes_raw()).decode("utf-8")
        return priv_b64, pub_b64

    @staticmethod
    def sign_message(message: str, private_key_b64: str) -> str:
        """Sign a message string using Ed25519 private key."""
        priv_bytes = base64.b64decode(private_key_b64)
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature = priv_key.sign(message.encode("utf-8"))
        return base64.b64encode(signature).decode("utf-8")

    @staticmethod
    def verify_signature(message: str, signature_b64: str, public_key_b64: str) -> bool:
        """Verify an Ed25519 digital signature against message and public key."""
        try:
            pub_bytes = base64.b64decode(public_key_b64)
            sig_bytes = base64.b64decode(signature_b64)
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub_key.verify(sig_bytes, message.encode("utf-8"))
            return True
        except Exception:
            return False
