# SENTINEL X — Security Architecture & Hardening Guide

## 1. Authentication & Token Lifecycle

* **Assertion Provider:** Firebase Authentication manages user credentials, OAuth providers, and password hashing (using Scrypt/Argon2 under Google infrastructure).
* **Server-side Verification:** The FastAPI backend inspects the `Authorization: Bearer <ID_TOKEN>` header on all protected endpoints using `firebase_admin.auth.verify_id_token`.
* **Revocation & Expiration Checking:** Token expiration is verified mathematically, and token revocation is checked where active sessions are tracked.
* **Tamper Proofing:** Tokens are signed using Google's private keys; clients cannot forge claims or fabricate user identifiers.

---

## 2. Role-Based Access Control (RBAC)

* **Server-Side Trust:** Roles are stored in Firestore user documents (`/users/{uid}`) and are strictly verified on the backend. No role claims supplied by frontend requests are trusted.
* **Immutability by Users:** Endpoints explicitly prohibit users from modifying their own `role` or `status`.
* **Three Defined Roles:**
  1. **Admin:** User management, role assignment, audit log inspection, global alerts, threat management, full dashboard access.
  2. **Security Analyst:** Threat investigation, URL phishing analysis, identity impersonation detection, login anomalies, behaviour telemetry, alert resolution, crypto operations.
  3. **User:** Personal profile access, personal alert reviews, submitting URLs for phishing scanning.
* **Anti-Lockout Protection:** An Administrator cannot demote or suspend their own account via the API.

---

## 3. Cryptographic Implementation

* **Authenticated Encryption:** AES-256-GCM using Python's official `cryptography` library (`hazmat.primitives.ciphers.aead.AESGCM`).
* **Nonce Hygiene:** Every encryption operation generates a unique, cryptographically secure 96-bit (12-byte) random nonce using `secrets.token_bytes(12)`. Nonces are never reused.
* **Tamper Detection:** AES-GCM generates a 128-bit authentication tag. Any modification to the ciphertext or Associated Authenticated Data (AAD) causes immediate decryption rejection (HTTP 400).
* **Key Separation:** Encryption keys are supplied via environment variables (`SENTINEL_MASTER_KEY`) and are never stored in the database alongside encrypted payloads.
* **Digital Signatures:** Ed25519 asymmetric signatures provide non-repudiation and high-speed cryptographic verification.
* **Post-Quantum Cryptography Note:** Standardized algorithms (NIST FIPS 203 ML-KEM and FIPS 204 ML-DSA) represent the target post-quantum transition architecture. The current production release uses established AES-256-GCM (which provides 128-bit quantum security against Grover's algorithm) and Ed25519.

---

## 4. Rate Limiting & Denial of Service Protection

* **Sliding Window Rate Limiter:** Protects against credential stuffing, brute force, and API abuse. Defaults to 60 requests per minute per IP address.
* **Request Entity Size Limit:** Restricts incoming HTTP payloads to a maximum of 2 MB (`MAX_REQUEST_SIZE_BYTES`) to prevent memory exhaustion and buffer inflation attacks.
* **Safe URL Processing:** The phishing engine parses and validates URL structures mathematically. It never opens suspicious URLs, never downloads external binaries, and never executes remote JavaScript.

---

## 5. Network & HTTP Hardening

* **CORS Allowlist:** Strict origin allowlist (`ALLOWED_ORIGINS`). Wildcard CORS (`*`) is explicitly prohibited in production mode.
* **Security Headers Injected by Middleware:**
  * `X-Content-Type-Options: nosniff` (prevents MIME-type sniffing)
  * `X-Frame-Options: DENY` (prevents Clickjacking)
  * `X-XSS-Protection: 1; mode=block`
  * `Referrer-Policy: strict-origin-when-cross-origin`
  * `Strict-Transport-Security: max-age=31536000; includeSubDomains` (enforces HTTPS in production)

---

## 6. Audit Logging & Information Disclosure

* **Zero Information Leakage:** Global exception handlers catch unhandled server errors and output generic HTTP 500 responses (`detail: An internal security error occurred`). Internal tracebacks, database schema details, and credentials are never sent to clients.
* **Append-Only Audit Trail:** Critical administrative and security actions (`USER_ROLE_CHANGED`, `ALERT_STATUS_UPDATED`, `CRITICAL_TIER_RESPONSE_TRIGGERED`) are written directly to the `audit_logs` collection in Firestore.
