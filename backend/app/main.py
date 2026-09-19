import time
import logging
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Dict, List

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.db.base import Base
from app.db.session import engine, AsyncSessionLocal
from app.services.bootstrap import bootstrap_roles_and_admin
from app.api.v1.api import api_router
from app.schemas.error import ProblemDetail

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("cyber_soc.main")

# Rate limiting in-memory storage (Client IP -> list of request timestamps)
rate_limit_records: Dict[str, List[float]] = defaultdict(list)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: runs database schema initialization and bootstraps admin account."""
    logger.info("Starting up Cyber SOC Autonomous Platform backend...")
    
    # Initialize tables if not already present
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema validated.")

    # Run idempotent bootstrap of standard roles and initial admin
    async with AsyncSessionLocal() as session:
        await bootstrap_roles_and_admin(session)
    logger.info("Bootstrap roles and administrator accounts verified.")

    yield

    logger.info("Shutting down Cyber SOC backend...")
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "An evidence-driven academic prototype integrating SIEM-style event ingestion, "
        "UEBA, anomaly detection, AI-assisted investigation, attack correlation, "
        "MITRE ATT&CK mapping, response simulation, human approval, and continuous learning."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# 1. CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 2. Request-Size Limiting & Rate Limiting Middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Request-Size Limit Check
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_REQUEST_SIZE_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content=ProblemDetail(
                title="Payload Too Large",
                status=413,
                detail=f"Request size exceeds maximum allowed threshold of {settings.MAX_REQUEST_SIZE_BYTES} bytes",
                instance=request.url.path
            ).model_dump()
        )

    # In-memory Rate Limiting (per client IP)
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    one_minute_ago = now - 60.0

    # Clean old requests
    timestamps = [t for t in rate_limit_records[client_ip] if t > one_minute_ago]
    if len(timestamps) >= settings.RATE_LIMIT_REQUESTS_PER_MINUTE:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=ProblemDetail(
                title="Too Many Requests",
                status=429,
                detail=f"Rate limit exceeded: maximum {settings.RATE_LIMIT_REQUESTS_PER_MINUTE} requests per minute",
                instance=request.url.path
            ).model_dump(),
            headers={"Retry-After": "60"}
        )

    timestamps.append(now)
    rate_limit_records[client_ip] = timestamps

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(settings.RATE_LIMIT_REQUESTS_PER_MINUTE)
    response.headers["X-RateLimit-Remaining"] = str(max(0, settings.RATE_LIMIT_REQUESTS_PER_MINUTE - len(timestamps)))
    return response


# 3. Structured Error Responses (RFC 7807)
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=ProblemDetail(
            title="HTTP Error",
            status=exc.status_code,
            detail=str(exc.detail),
            instance=request.url.path
        ).model_dump(),
        headers=getattr(exc, "headers", None)
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled system exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ProblemDetail(
            title="Internal Server Error",
            status=500,
            detail="An internal server error occurred. System telemetry has been logged.",
            instance=request.url.path
        ).model_dump()
    )


# 4. Mount API Routes
app.include_router(api_router, prefix=settings.API_V1_STR)

# Top-level direct health alias for Docker / load-balancer probes
@app.get("/health", tags=["Health Diagnostics"])
async def root_health():
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "classification": "ACADEMIC_PROTOTYPE_SIMULATION_ONLY"
    }
