# SENTINEL X — Setup and Deployment Guide

## 1. Prerequisites

* Python 3.10+ (tested on Python 3.11 and 3.15)
* Firebase Project with Authentication (Email/Password or Google Sign-In) and Cloud Firestore enabled.

---

## 2. Local Environment Setup

### Step 1: Clone or Navigate to the Project Directory
```bash
cd sentinel-x-backend
```

### Step 2: Create a Virtual Environment
```bash
# On Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# On Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

---

## 3. Environment Configuration

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Edit `.env` to configure your settings:
```ini
ENVIRONMENT=development
DEBUG=true
APP_NAME=SENTINEL_X_BACKEND
API_V1_PREFIX=/api/v1

# Frontend Origin(s)
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:5500

# Firebase Project Configuration
FIREBASE_PROJECT_ID=your-firebase-project-id
FIREBASE_CREDENTIALS_PATH=serviceAccountKey.json

# Master Cryptography Key (32-byte Base64 key)
SENTINEL_MASTER_KEY=k8qY3mR1wH2bV9tL7oP5xJ0nU4zF6gC8eD1sA3vK5yI=

# Rate Limit (requests/min/IP)
RATE_LIMIT_PER_MINUTE=60
```

### Adding Firebase Service Account Credentials
1. Go to your [Firebase Console](https://console.firebase.google.com/) -> Project Settings -> Service accounts.
2. Click **Generate new private key**.
3. Save the downloaded JSON file as `serviceAccountKey.json` inside `sentinel-x-backend/`.
4. *Note: `serviceAccountKey.json` is already included in `.gitignore` to prevent accidental commit.*

---

## 4. Running the Application

Start the FastAPI application with Uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Once running:
* **Interactive API Documentation (Swagger UI):** `http://localhost:8000/docs`
* **Alternative API Documentation (ReDoc):** `http://localhost:8000/redoc`
* **Health Check:** `http://localhost:8000/health`

---

## 5. Running the Automated Test Suite

Run pytest to execute all unit, integration, RBAC, cryptographic, and security tests:
```bash
pytest -v
```
All 28 tests execute in isolation using the built-in in-memory Firestore engine and cryptographic test fixtures.
