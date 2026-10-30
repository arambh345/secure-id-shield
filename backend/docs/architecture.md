# SENTINEL X — Backend Architecture

## System Overview

**SENTINEL X** is an intelligent cyber identity, threat detection, and cryptographic security system built on a zero-trust architecture. It integrates with Firebase Authentication for identity assertions, Google Cloud Firestore for persistent security telemetry, and provides real-time threat intelligence through algorithmic detection engines.

```
                    +---------------------------+
                    |    Client / Frontend      |
                    +-------------+-------------+
                                  |
                                  | HTTPS / Bearer ID Token
                                  v
+---------------------------------+---------------------------------+
|                        SENTINEL X API                             |
|                                                                   |
|   +-------------------+    +-------------------+                  |
|   | Security Headers  |--->| Rate Limiter      |                  |
|   | & Request Limiter |    | (Sliding Window)  |                  |
|   +-------------------+    +---------+---------+                  |
|                                      |                            |
|                                      v                            |
|                   +------------------+------------------+         |
|                   | Firebase Auth & RBAC Verification   |         |
|                   | (Admin / Security Analyst / User)   |         |
|                   +------------------+------------------+         |
|                                      |                            |
|        +-----------------------------+-----------------------+    |
|        |                             |                       |    |
|        v                             v                       v    |
|  +------------+              +---------------+        +---------+ |
|  |  Phishing  |              | Impersonation |        | Anomaly | |
|  |  Detector  |              |    Engine     |        | Service | |
|  +-----+------+              +-------+-------+        +----+----+ |
|        |                             |                     |      |
|        +-----------------------------+---------------------+      |
|                                      |                            |
|                                      v                            |
|                       +--------------+-------------+              |
|                       |  Weighted Risk Engine     |              |
|                       |  (Tiers 1 - 4 Response)    |              |
|                       +--------------+-------------+              |
|                                      |                            |
|                                      v                            |
|                       +--------------+-------------+              |
|                       | Alert & Audit Logging Svc  |              |
|                       +--------------+-------------+              |
|                                      |                            |
+--------------------------------------+----------------------------+
                                       |
                                       v
                        +--------------+-------------+
                        |   Google Cloud Firestore   |
                        |   (Collections & Security) |
                        +----------------------------+
```

## Module Responsibilities

1. **`app/main.py`**:
   - Application entrypoint, lifespan configuration, CORS, rate limiting middleware, request body size limits, hardened security headers, and global exception handlers.

2. **`app/config.py`**:
   - Centralized typed configuration using Pydantic Settings. Reads from `.env` with validation.

3. **`app/firebase.py`**:
   - Initializes Firebase Admin SDK with service-account credentials or emulator host. Provides Firestore client and ID token verification.

4. **`app/core/auth.py`**:
   - Extracts Bearer token, verifies Firebase signature and revocation status, auto-synchronizes user records in Firestore, and checks account status.

5. **`app/core/permissions.py`**:
   - Defines `UserRole` (`Admin`, `Security Analyst`, `User`). Enforces role requirements on protected endpoints. Prevents privilege self-escalation.

6. **`app/core/security.py`**:
   - Sliding-window in-memory rate limiting, safe URL validation, and persistent audit logging to the `audit_logs` collection.

7. **`app/services/`**:
   - `phishing_service.py`: Heuristic URL analysis (Punycode/homograph, raw IP hosts, brand lookalikes, Shannon entropy, suspicious TLDs, keyword matching).
   - `impersonation_service.py`: Executive and identity spoofing detector (homoglyphs, Jaro/Levenshtein similarity, email domain typosquatting).
   - `anomaly_service.py`: Authentication baseline tracking (brute force detection, new devices/user-agents, impossible travel, unusual hours).
   - `risk_service.py`: Transparent composite risk engine (0-100 scale, Low/Medium/High/Critical severity, Tier 1-4 recommended responses).
   - `crypto_service.py`: Authenticated AES-256-GCM encryption, SHA-256 hashing, and Ed25519 digital signatures.
   - `alert_service.py`: Deduplicated alert generation, resolution workflows, and tiered automated responses.

## Firestore Data Flow

All persistent records are stored in Cloud Firestore under 7 dedicated collections:
- `users`: Synchronized user profiles, roles, and account status.
- `login_events`: Authentication telemetry, device IDs, and anomaly scores.
- `behaviour_logs`: Security-sensitive user action telemetry.
- `threats`: Detected phishing URLs and impersonation records.
- `alerts`: Security incidents with acknowledgement and resolution statuses.
- `audit_logs`: Immutable security event log.
- `security_settings`: Tenant-wide configuration parameters.
