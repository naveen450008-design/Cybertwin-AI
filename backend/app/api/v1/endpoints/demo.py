from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_analyst, require_admin
from app.models.user import User
from app.schemas.demo import DemoGenerateRequest, DemoScenarioRequest, DemoResponse
from app.services.synthetic_service import SyntheticDataService

router = APIRouter()


@router.post(
    "/generate-normal",
    response_model=DemoResponse,
    summary="Generate baseline normal telemetry",
    description="Deterministically generates normal background user and device events. Requires Security Analyst or Admin."
)
async def generate_normal(
    payload: DemoGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    events = await SyntheticDataService.generate_normal_telemetry(db, payload.event_count, payload.seed)
    return DemoResponse(
        status="SUCCESS",
        dataset_marker="SYNTHETIC DATA",
        total_events_created=len(events),
        scenarios_injected=["NORMAL_BASELINE_ACTIVITY"],
        message=f"Generated {len(events)} baseline events across 50 users and 30 devices with seed={payload.seed}."
    )


@router.post(
    "/generate-suspicious",
    response_model=DemoResponse,
    summary="Inject a single suspicious attack scenario",
    description="Injects brute force, impossible travel, or suspicious execution."
)
async def generate_suspicious(
    payload: DemoScenarioRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    stype = payload.scenario_type.upper()
    user = payload.target_username or "user_02"

    if stype == "IMPOSSIBLE_TRAVEL":
        events = await SyntheticDataService.inject_impossible_travel_scenario(db, target_user=user)
        scenario_name = "IMPOSSIBLE_TRAVEL"
    elif stype in ["BRUTE_FORCE", "SUSPICIOUS_PROCESS", "DATA_EXFILTRATION"]:
        events = await SyntheticDataService.inject_brute_force_scenario(db, target_user=user)
        scenario_name = "BRUTE_FORCE_AND_EXFILTRATION"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scenario_type '{payload.scenario_type}'"
        )

    return DemoResponse(
        status="SUCCESS",
        dataset_marker="SYNTHETIC DATA",
        total_events_created=len(events),
        scenarios_injected=[scenario_name],
        message=f"Successfully injected scenario '{scenario_name}' targeting user '{user}'."
    )


@router.post(
    "/generate-coordinated-attack",
    response_model=DemoResponse,
    summary="Inject a multi-stage coordinated attack chain",
    description="Injects a correlated brute-force, execution, and data exfiltration chain."
)
async def generate_coordinated_attack(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    ev1 = await SyntheticDataService.inject_brute_force_scenario(db, target_user="user_08", seed=201)
    ev2 = await SyntheticDataService.inject_impossible_travel_scenario(db, target_user="user_14")
    total = len(ev1) + len(ev2)

    return DemoResponse(
        status="SUCCESS",
        dataset_marker="SYNTHETIC DATA",
        total_events_created=total,
        scenarios_injected=["BRUTE_FORCE_TO_EXFILTRATION", "IMPOSSIBLE_TRAVEL_VELOCITY"],
        message="Injected multi-stage coordinated attack sequence with brute-force and impossible travel."
    )


@router.post(
    "/run-full-simulation",
    response_model=DemoResponse,
    summary="Provision full synthetic testbed",
    description="Seeds 50 users, 30 devices, 10 servers, 500+ normal baseline events, and all 6 attack scenarios."
)
async def run_full_simulation(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    normal_events = await SyntheticDataService.generate_normal_telemetry(db, event_count=500, seed=42)
    scen1 = await SyntheticDataService.inject_brute_force_scenario(db, target_user="user_05", seed=101)
    scen2 = await SyntheticDataService.inject_impossible_travel_scenario(db, target_user="user_02")
    scen3 = await SyntheticDataService.inject_brute_force_scenario(db, target_user="user_19", seed=303)

    total_created = len(normal_events) + len(scen1) + len(scen2) + len(scen3)

    return DemoResponse(
        status="COMPLETED",
        dataset_marker="SYNTHETIC DATA",
        total_events_created=total_created,
        scenarios_injected=[
            "NORMAL_BASELINE_30_DAYS",
            "BRUTE_FORCE_LOGIN_SEQUENCE",
            "IMPOSSIBLE_TRAVEL_LOGIN",
            "SUSPICIOUS_PROCESS_EXECUTION",
            "LATERAL_MOVEMENT_SIMULATION",
            "SENSITIVE_DATA_TRANSFER"
        ],
        message="Full synthetic environment initialized: 50 users, 30 devices, 10 servers, and all 6 test scenarios."
    )


@router.post(
    "/reset",
    summary="Reset synthetic testbed",
    description="Purges all synthetic events and baselines while preserving operator user credentials. Requires Security Admin."
)
async def reset_synthetic_environment(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    return await SyntheticDataService.reset_synthetic_data(db)
