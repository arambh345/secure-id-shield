"""SENTINEL X Backend Main Application Entrypoint."""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.firebase import initialize_firebase
from app.core.security import rate_limiter
from app.routes import (
    users,
    phishing,
    impersonation,
    login,
    behaviour,
    risk,
    cryptography,
    alerts,
    dashboard,
)

# Configure structured logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info("Starting up %s (Environment: %s)...", settings.APP_NAME, settings.ENVIRONMENT)
    # Initialize Firebase Admin SDK
    initialize_firebase()
    yield
    logger.info("Shutting down %s...", settings.APP_NAME)


# Create FastAPI instance with strict OpenAPI metadata
app = FastAPI(
    title="SENTINEL X — Cyber Identity & Threat Detection API",
    description="Intelligent Cyber Identity, Threat Detection, and Cryptographic Security System.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# 1. Custom Security Headers & Request Size Middleware
class SecurityHeadersAndSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 1. Request Body Size Limit Check
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.MAX_REQUEST_SIZE_BYTES:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Request body size exceeds maximum allowed threshold (2 MB)."},
                    )
            except ValueError:
                pass

        # 2. Rate Limiting Check
        client_ip = request.client.host if request.client else "127.0.0.1"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

        # Exempt health check and docs from strict rate limit
        path = request.url.path
        if not (path == "/health" or path == "/" or path.startswith("/docs") or path.startswith("/openapi")):
            if rate_limiter.is_rate_limited(client_ip):
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Rate limit exceeded. Please wait before retrying."},
                    headers={"Retry-After": "60"},
                )

        response = await call_next(request)

        # 3. Apply Hardened Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


app.add_middleware(SecurityHeadersAndSizeMiddleware)

# 2. CORS Middleware Configuration
cors_origins = settings.ALLOWED_ORIGINS
if settings.is_production and ("*" in cors_origins):
    logger.warning("Wildcard CORS detected in production configuration! Reverting to restrictive default.")
    cors_origins = ["https://sentinel-x.app"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
)


# 3. Secure Global Exception Handlers (Never leak stack traces or internals)
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        field_name = " -> ".join(str(loc) for loc in err.get("loc", []))
        errors.append(f"{field_name}: {err.get('msg')}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Input validation error", "errors": errors},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled internal server error: %s", str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal security error occurred. The incident has been recorded."},
    )


# 4. Root & Health Endpoints
@app.get("/", tags=["System"])
async def root():
    return {
        "system": "SENTINEL X",
        "description": "Intelligent Cyber Identity, Threat Detection and Cryptographic Security System",
        "version": "1.0.0",
        "status": "OPERATIONAL",
        "docs_url": "/docs",
    }


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "HEALTHY",
        "environment": settings.ENVIRONMENT,
        "firebase_project": settings.FIREBASE_PROJECT_ID,
    }


# 5. Include Versioned API Routers (/api/v1)
prefix = settings.API_V1_PREFIX
app.include_router(users.router, prefix=prefix)
app.include_router(phishing.router, prefix=prefix)
app.include_router(impersonation.router, prefix=prefix)
app.include_router(login.router, prefix=prefix)
app.include_router(behaviour.router, prefix=prefix)
app.include_router(risk.router, prefix=prefix)
app.include_router(cryptography.router, prefix=prefix)
app.include_router(alerts.router, prefix=prefix)
app.include_router(dashboard.router, prefix=prefix)
