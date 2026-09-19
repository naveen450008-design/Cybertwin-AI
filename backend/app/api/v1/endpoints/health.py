from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import settings
from app.schemas.health import HealthResponse

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System health check",
    description="Returns service uptime status, version, timestamp, and database operational state."
)
async def check_health(db: AsyncSession = Depends(get_db)) -> HealthResponse:
    db_status = "ONLINE"
    db_error = None
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = "DEGRADED"
        db_error = str(e)

    return HealthResponse(
        status="healthy" if db_status == "ONLINE" else "degraded",
        version=settings.VERSION,
        timestamp=datetime.now(timezone.utc),
        database=db_status,
        details={
            "service": settings.PROJECT_NAME,
            "api_version": settings.VERSION,
            "database_error": db_error,
            "security_mode": "ACADEMIC_PROTOTYPE_SIMULATION_ONLY"
        }
    )


@router.get(
    "/health/ready",
    summary="Kubernetes / Docker readiness probe",
    description="Returns 200 OK when database connection is live and accepting transactions."
)
async def check_readiness(db: AsyncSession = Depends(get_db)) -> dict:
    await db.execute(text("SELECT 1"))
    return {"status": "READY", "timestamp": datetime.now(timezone.utc).isoformat()}
