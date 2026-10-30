"""Test fixtures and configurations for SENTINEL X."""

import os
import pytest
from fastapi.testclient import TestClient

# Ensure test settings before importing app
os.environ["ENVIRONMENT"] = "testing"
os.environ["FIREBASE_USE_EMULATOR"] = "false"
os.environ["SENTINEL_MASTER_KEY"] = "k8qY3mR1wH2bV9tL7oP5xJ0nU4zF6gC8eD1sA3vK5yI="
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000,http://127.0.0.1:5500"

from app.main import app
from app.firebase import _mock_firestore
from app.core.security import rate_limiter


@pytest.fixture(autouse=True)
def reset_mock_state():
    """Reset in-memory storage and rate limiter state before each test."""
    _mock_firestore.reset()
    rate_limiter.reset()
    yield


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_headers():
    """Auth headers for an Administrator."""
    return {"Authorization": "Bearer sentinel-test-token:admin-user:Admin"}


@pytest.fixture
def analyst_headers():
    """Auth headers for a Security Analyst."""
    return {"Authorization": "Bearer sentinel-test-token:analyst-user:Security Analyst"}


@pytest.fixture
def user_headers():
    """Auth headers for a regular User."""
    return {"Authorization": "Bearer sentinel-test-token:regular-user:User"}
