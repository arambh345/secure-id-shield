# SENTINEL X — Cyber Identity, Threat Detection & Cryptographic Security System

SENTINEL X is an enterprise-grade cyber defense and identity security platform designed for modern zero-trust architectures. It integrates Firebase Authentication, Cloud Firestore telemetry, multi-vector threat detection, and authenticated cryptographic operations.

---

## Key Modules & Features

1. **Cyber Identity & Access Control (RBAC):**
   * Real-time Firebase ID token verification.
   * Three-tiered role-based authorization: **Admin**, **Security Analyst**, and **User**.
   * Anti-lockout self-demotion protection and automated user profile synchronization in Firestore.

2. **Intelligent Phishing & URL Threat Detection:**
   * Algorithmic analysis of suspicious URL structures and protocols.
   * Punycode / IDN homograph detection (Cyrillic and visual lookalike spoofing).
   * Brand typosquatting and Levenshtein lookalike distance mapping against high-profile targets.
   * Raw IP host detection, Shannon entropy calculations for DGA domains, and credential harvesting keyword matching.

3. **Identity Impersonation Engine:**
   * Executive and corporate identity spoofing detection.
   * Visual Unicode homoglyph normalization and leetspeak substitution detection.
   * Email domain typosquatting detection for supply-chain and executive phishing vectors.

4. **Login Anomaly & Behavioral Baselines:**
   * Device and hardware signature monitoring.
   * Rapid authentication velocity (impossible travel / IP shift) detection.
   * Brute force and credential stuffing detection with consecutive failure tracking.
   * Behavioral activity logging for high-risk access events.

5. **Transparent Weighted Risk Engine:**
   * Multi-signal weighted risk scoring on a calibrated 0–100 scale.
   * Configurable threshold tiers (Low, Medium, High, Critical) mapped to automated defensive responses (Tier 1–4).

6. **Cryptographic Defense Module:**
   * Authenticated **AES-256-GCM** encryption with unique 96-bit nonces and 128-bit authentication tags.
   * Tamper-evident versioned payload packaging (`v1:{nonce}:{payload}`).
   * **SHA-256** integrity verification and **Ed25519** high-speed digital signatures.

7. **Security Alert & Incident Response:**
   * Real-time security alert creation with deduplication window.
   * Administrative acknowledgement and resolution workflows with complete audit logging.

8. **Hardened API Gateway:**
   * Sliding-window rate limiting per IP.
   * Request body size limiting (2 MB max).
   * Hardened security headers (`nosniff`, `DENY`, `XSS-Protection`).
   * Strict CORS allowlist prohibiting wildcard origins in production.

---

## Technology Stack

* **Language:** Python 3.10+
* **Framework:** FastAPI
* **Database & Auth:** Firebase Authentication & Cloud Firestore (Firebase Admin SDK)
* **Data Validation:** Pydantic v2 & Pydantic Settings
* **Cryptography:** Python `cryptography` library (AES-GCM, Ed25519, SHA-256)
* **Testing:** Pytest (28 automated tests passing)

---

## Quickstart

```bash
# 1. Navigate to backend directory
cd sentinel-x-backend

# 2. Activate virtual environment
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy and configure environment variables
cp .env.example .env

# 5. Run tests
pytest -v

# 6. Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

* **Swagger UI:** `http://localhost:8000/docs`
* **ReDoc:** `http://localhost:8000/redoc`
* **Health Check:** `http://localhost:8000/health`
