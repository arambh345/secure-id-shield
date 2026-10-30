# SENTINEL X — API Reference Manual

All endpoints are versioned under `/api/v1`. Authentication requires an `Authorization: Bearer <FIREBASE_ID_TOKEN>` header on protected endpoints.

---

## 1. System Endpoints

### Health Check
* **Endpoint:** `GET /health`
* **Auth Required:** No
* **Response (200 OK):**
```json
{
  "status": "HEALTHY",
  "environment": "development",
  "firebase_project": "sentinel-x-demo"
}
```

---

## 2. User & Identity Management (`/api/v1/users`)

### Get Current User Profile
* **Endpoint:** `GET /api/v1/users/me`
* **Auth Required:** Yes (Any valid role)
* **Response (200 OK):**
```json
{
  "uid": "usr_991823",
  "email": "analyst@sentinel.internal",
  "display_name": "Security Analyst",
  "role": "Security Analyst",
  "status": "active",
  "mfa_enabled": false,
  "created_at": "2026-10-30T10:00:00Z"
}
```

### Update Current User Profile
* **Endpoint:** `PATCH /api/v1/users/me`
* **Auth Required:** Yes
* **Request Body:**
```json
{
  "display_name": "Alex Mercer",
  "phone_number": "+1555019283"
}
```

### List All Users
* **Endpoint:** `GET /api/v1/users`
* **Auth Required:** Yes (Role: `Admin`)

### Update User Role
* **Endpoint:** `PATCH /api/v1/users/{user_id}/role`
* **Auth Required:** Yes (Role: `Admin`)
* **Request Body:**
```json
{
  "role": "Security Analyst"
}
```

---

## 3. Phishing & URL Detection (`/api/v1/phishing`)

### Analyze URL
* **Endpoint:** `POST /api/v1/phishing/analyze`
* **Auth Required:** Yes (All roles)
* **Request Body:**
```json
{
  "url": "http://192.168.1.1/paypa1-security/login"
}
```
* **Response (200 OK):**
```json
{
  "url": "http://192.168.1.1/paypa1-security/login",
  "findings": [
    "Insecure plain HTTP protocol in use",
    "Host uses raw IP address instead of domain name: 192.168.1.1",
    "Security/credential harvesting keywords found in path/query: login, security"
  ],
  "risk_score": 75,
  "severity": "High",
  "explanation": "URL exhibits strong suspicious indicators such as lookalike branding or credential obfuscation.",
  "analyzed_at": "2026-10-30T10:15:00Z"
}
```

---

## 4. Identity Impersonation (`/api/v1/impersonation`)

### Check Candidate Identity
* **Endpoint:** `POST /api/v1/impersonation/check`
* **Auth Required:** Yes (`Security Analyst`, `Admin`)
* **Request Body:**
```json
{
  "candidate_name": "Adm1nistrator",
  "candidate_email": "adm1n@sent1nel.internal"
}
```
* **Response (200 OK):**
```json
{
  "candidate_name": "Adm1nistrator",
  "candidate_email": "adm1n@sent1nel.internal",
  "similarity_score": 0.88,
  "risk_score": 88,
  "severity": "Critical",
  "matched_target": {
    "name": "Administrator",
    "email": "admin@sentinel.internal",
    "role": "Admin"
  },
  "findings": [
    "High-confidence 1-character typo/lookalike of target 'Administrator'"
  ],
  "explanation": "Candidate demonstrates clear signs of targeted identity spoofing or homoglyph impersonation.",
  "checked_at": "2026-10-30T10:16:00Z"
}
```

---

## 5. Login & Access Anomalies (`/api/v1/login`)

### Record Login Event
* **Endpoint:** `POST /api/v1/login/events`
* **Auth Required:** Yes
* **Request Body:**
```json
{
  "user_id": "usr_991823",
  "device_id": "HW-MAC-9821A",
  "location": "Berlin, Germany",
  "login_successful": true
}
```

### Get Login Anomalies
* **Endpoint:** `GET /api/v1/login/anomalies?min_severity=Medium`
* **Auth Required:** Yes (`Security Analyst`, `Admin`)

---

## 6. Behavior Monitoring (`/api/v1/behaviour`)

### Record Behaviour Event
* **Endpoint:** `POST /api/v1/behaviour/events`
* **Auth Required:** Yes
* **Request Body:**
```json
{
  "action": "MASS_DATA_EXPORT",
  "resource": "customer_credentials_table",
  "risk_level": "High",
  "metadata": {"records_count": 5000}
}
```

### Get Behaviour Logs
* **Endpoint:** `GET /api/v1/behaviour/logs`
* **Auth Required:** Yes (`Security Analyst`, `Admin`)

---

## 7. Risk Scoring Engine (`/api/v1/risk`)

### Calculate Composite Risk
* **Endpoint:** `POST /api/v1/risk/calculate`
* **Auth Required:** Yes
* **Request Body:**
```json
{
  "source": "Endpoint EDR",
  "phishing_score": 75,
  "impersonation_score": 60,
  "login_anomaly_score": 80
}
```
* **Response (200 OK):**
```json
{
  "risk_score": 73,
  "severity": "High",
  "reasons": [
    "Phishing analysis contributed risk weight: score 75/100",
    "Identity impersonation indicators contributed risk weight: score 60/100",
    "Authentication anomalies contributed risk weight: score 80/100"
  ],
  "detection_source": "Endpoint EDR",
  "recommended_response": "Tier 3: Challenge user with step-up multi-factor authentication (MFA) and notify Security Analyst.",
  "timestamp": "2026-10-30T10:18:00Z"
}
```

---

## 8. Cryptography Module (`/api/v1/crypto`)

### Encrypt Data
* **Endpoint:** `POST /api/v1/crypto/encrypt`
* **Auth Required:** Yes (`Security Analyst`, `Admin`)
* **Request Body:**
```json
{
  "plaintext": "CONFIDENTIAL_PAYLOAD",
  "associated_data": "record_id_102"
}
```

### Decrypt Data
* **Endpoint:** `POST /api/v1/crypto/decrypt`
* **Auth Required:** Yes (`Security Analyst`, `Admin`)
* **Request Body:**
```json
{
  "versioned_package": "v1:nonce_base64:payload_base64",
  "associated_data": "record_id_102"
}
```

### Verify Integrity or Digital Signature
* **Endpoint:** `POST /api/v1/crypto/verify`
* **Auth Required:** Yes (`Security Analyst`, `Admin`)
* **Request Body:**
```json
{
  "message": "SECURITY_DISPATCH_MESSAGE",
  "hash_sha256": "4b92b67...",
  "signature": "base64_ed25519_sig...",
  "public_key": "base64_ed25519_pub..."
}
```

---

## 9. Alerts & Incident Response (`/api/v1/alerts`)

### List Alerts
* **Endpoint:** `GET /api/v1/alerts`
* **Auth Required:** Yes (Regular users see only their alerts; Analysts and Admins see all)

### Acknowledge / Resolve Alert
* **Endpoint:** `PATCH /api/v1/alerts/{alert_id}`
* **Auth Required:** Yes (`Security Analyst`, `Admin`)
* **Request Body:**
```json
{
  "acknowledged": true,
  "resolved": true,
  "notes": "Threat quarantined and perimeter firewall updated."
}
```

---

## 10. Dashboard Overview (`/api/v1/dashboard`)

### Get Security Posture Metrics
* **Endpoint:** `GET /api/v1/dashboard/overview`
* **Auth Required:** Yes (`Security Analyst`, `Admin`)
* **Response (200 OK):** Returns total users, active threats, open alerts, severity breakdown, and recent security events.
