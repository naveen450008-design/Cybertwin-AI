from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth, health, events, demo, incidents, simulation, audit, copilot, governance, ip_intelligence
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & RBAC"])
api_router.include_router(events.router, prefix="/events", tags=["Security Event Ingestion"])
api_router.include_router(demo.router, prefix="/demo", tags=["Synthetic Demo Environment"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incident Management & Investigation"])
api_router.include_router(simulation.router, prefix="/simulation", tags=["Digital Twin & Safe Response Simulation"])
api_router.include_router(audit.router, prefix="/audit", tags=["Cryptographic Audit Ledger"])
api_router.include_router(copilot.router, prefix="/copilot", tags=["AI Investigation Copilot"])
api_router.include_router(governance.router, prefix="/governance", tags=["Model Governance & Continuous Learning"])
api_router.include_router(ip_intelligence.router, prefix="/ip-intelligence", tags=["IP Threat Intelligence"])
api_router.include_router(health.router, prefix="", tags=["Health Diagnostics"])

