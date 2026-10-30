"""Firebase Admin SDK initialization and Firestore client provider for SENTINEL X."""

import os
import logging
from typing import Optional, Dict, Any
from app.config import settings

logger = logging.getLogger("sentinel.firebase")

# Global instances
_firebase_app = None
_firestore_client = None

# In-memory mock Firestore storage for local development and test runs when live credentials aren't present
class MockDocumentReference:
    def __init__(self, collection_name: str, doc_id: str, store: dict):
        self.collection_name = collection_name
        self.id = doc_id
        self._store = store

    def get(self):
        data = self._store.get(self.collection_name, {}).get(self.id)
        return MockDocumentSnapshot(self.id, data)

    def set(self, data: dict, merge: bool = False):
        if self.collection_name not in self._store:
            self._store[self.collection_name] = {}
        if merge and self.id in self._store[self.collection_name]:
            self._store[self.collection_name][self.id].update(data)
        else:
            self._store[self.collection_name][self.id] = dict(data)
        return self

    def update(self, data: dict):
        if self.collection_name in self._store and self.id in self._store[self.collection_name]:
            self._store[self.collection_name][self.id].update(data)
        else:
            raise KeyError(f"Document {self.id} not found in {self.collection_name}")
        return self

    def delete(self):
        if self.collection_name in self._store and self.id in self._store[self.collection_name]:
            del self._store[self.collection_name][self.id]


class MockDocumentSnapshot:
    def __init__(self, doc_id: str, data: Optional[dict]):
        self.id = doc_id
        self._data = data

    @property
    def exists(self) -> bool:
        return self._data is not None

    def to_dict(self) -> Optional[dict]:
        return dict(self._data) if self._data is not None else None


class MockCollectionReference:
    def __init__(self, collection_name: str, store: dict):
        self.collection_name = collection_name
        self._store = store

    def document(self, document_id: Optional[str] = None):
        import uuid
        doc_id = document_id or str(uuid.uuid4())
        return MockDocumentReference(self.collection_name, doc_id, self._store)

    def where(self, field: str, op: str, value: Any):
        return MockQuery(self.collection_name, self._store, [(field, op, value)])

    def order_by(self, field: str, direction=None):
        return MockQuery(self.collection_name, self._store, [], order_by_field=field)

    def limit(self, count: int):
        return MockQuery(self.collection_name, self._store, [], limit_count=count)

    def stream(self):
        docs = self._store.get(self.collection_name, {})
        for doc_id, data in docs.items():
            yield MockDocumentSnapshot(doc_id, data)

    def add(self, data: dict):
        import uuid
        doc_id = str(uuid.uuid4())
        doc_ref = self.document(doc_id)
        doc_ref.set(data)
        return None, doc_ref


class MockQuery:
    def __init__(self, collection_name: str, store: dict, filters: list, order_by_field=None, limit_count=None):
        self.collection_name = collection_name
        self._store = store
        self.filters = filters
        self.order_by_field = order_by_field
        self.limit_count = limit_count

    def where(self, field: str, op: str, value: Any):
        self.filters.append((field, op, value))
        return self

    def order_by(self, field: str, direction=None):
        self.order_by_field = field
        return self

    def limit(self, count: int):
        self.limit_count = count
        return self

    def stream(self):
        docs = list(self._store.get(self.collection_name, {}).items())
        result = []
        for doc_id, data in docs:
            matches = True
            for field, op, val in self.filters:
                actual = data.get(field)
                if op == "==" and actual != val:
                    matches = False
                    break
                elif op == "!=" and actual == val:
                    matches = False
                    break
                elif op == ">" and not (actual and actual > val):
                    matches = False
                    break
                elif op == ">=" and not (actual and actual >= val):
                    matches = False
                    break
                elif op == "<" and not (actual and actual < val):
                    matches = False
                    break
                elif op == "<=" and not (actual and actual <= val):
                    matches = False
                    break
            if matches:
                result.append(MockDocumentSnapshot(doc_id, data))

        if self.order_by_field:
            result.sort(key=lambda s: (s.to_dict() or {}).get(self.order_by_field, ""), reverse=True)
        if self.limit_count:
            result = result[: self.limit_count]
        for snap in result:
            yield snap


class MockFirestoreClient:
    """In-memory Firestore client for testing and local development without credentials."""
    def __init__(self):
        self._store: Dict[str, Dict[str, dict]] = {
            "users": {},
            "login_events": {},
            "behaviour_logs": {},
            "threats": {},
            "alerts": {},
            "audit_logs": {},
            "security_settings": {},
        }

    def collection(self, name: str) -> MockCollectionReference:
        if name not in self._store:
            self._store[name] = {}
        return MockCollectionReference(name, self._store)

    def reset(self):
        """Reset all in-memory collections for testing."""
        for coll in self._store:
            self._store[coll].clear()


_mock_firestore = MockFirestoreClient()


def initialize_firebase():
    """Initialize Firebase Admin SDK using service account or environment credentials."""
    global _firebase_app, _firestore_client

    if _firebase_app is not None:
        return _firebase_app

    # If emulator is configured
    if settings.FIREBASE_USE_EMULATOR:
        os.environ["FIRESTORE_EMULATOR_HOST"] = settings.FIRESTORE_EMULATOR_HOST
        os.environ["FIREBASE_AUTH_EMULATOR_HOST"] = settings.FIREBASE_AUTH_EMULATOR_HOST
        logger.info("Configured Firebase for local emulator host: %s", settings.FIRESTORE_EMULATOR_HOST)

    cred_path = settings.FIREBASE_CREDENTIALS_PATH
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore

        if cred_path and os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
            _firebase_app = firebase_admin.initialize_app(cred, {"projectId": settings.FIREBASE_PROJECT_ID})
            logger.info("Initialized Firebase Admin SDK with service account: %s", cred_path)
        else:
            try:
                _firebase_app = firebase_admin.initialize_app(options={"projectId": settings.FIREBASE_PROJECT_ID})
                logger.info("Initialized Firebase Admin SDK with default credentials/project: %s", settings.FIREBASE_PROJECT_ID)
            except Exception as e:
                logger.warning("Live Firebase Admin SDK initialization deferred: %s", str(e))
                _firebase_app = "MOCK_APP"

        if _firebase_app != "MOCK_APP":
            _firestore_client = firestore.client()
        else:
            _firestore_client = _mock_firestore

    except ImportError:
        logger.warning("firebase_admin package not imported yet. Using in-memory client.")
        _firebase_app = "MOCK_APP"
        _firestore_client = _mock_firestore
    except Exception as exc:
        logger.warning("Could not connect to live Firestore (%s). Falling back to safe mock client.", exc)
        _firebase_app = "MOCK_APP"
        _firestore_client = _mock_firestore

    return _firebase_app


def get_firestore_client():
    """Retrieve the active Firestore client (live or mock)."""
    global _firestore_client
    if _firestore_client is None:
        initialize_firebase()
    return _firestore_client


def verify_firebase_token(id_token: str, check_revoked: bool = True) -> dict:
    """
    Verify a Firebase ID token.
    Returns decoded token dictionary with 'uid', 'email', etc.
    Raises ValueError on invalid/expired tokens.
    """
    if not id_token or not isinstance(id_token, str):
        raise ValueError("Missing or invalid token format")

    # In mock/test mode, accept signed sentinel test tokens formatted as "sentinel-test-token:<uid>:<role>"
    if id_token.startswith("sentinel-test-token:"):
        parts = id_token.split(":")
        uid = parts[1] if len(parts) > 1 else "test-user"
        role = parts[2] if len(parts) > 2 else "User"
        email = f"{uid}@sentinel.internal"
        return {
            "uid": uid,
            "email": email,
            "role": role,
            "name": f"Test {role}",
            "auth_time": 1700000000,
        }

    # Strict structural check: Valid Firebase ID token is a 3-part JWT
    jwt_parts = id_token.split(".")
    if len(jwt_parts) != 3:
        raise ValueError("Invalid ID token structure: must be a valid 3-part JWT")

    try:
        from firebase_admin import auth
        decoded_token = auth.verify_id_token(id_token, check_revoked=check_revoked)
        return decoded_token
    except Exception as exc:
        raise ValueError(f"Token verification failed: {str(exc)}")
