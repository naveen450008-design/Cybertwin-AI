import hashlib
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.asset import Asset
from app.models.event import SecurityEvent
from app.models.ingestion import IngestionBatch
from app.models.ueba import UEBABaseline
from app.services.ueba_service import UEBAService
from app.services.detection_rules import DetectionRuleEngine
from app.services.ml_anomaly_service import MLAnomalyService

CITIES = [
    "New York, USA", "London, UK", "Berlin, Germany", "Paris, France",
    "Tokyo, Japan", "Sydney, Australia", "Singapore", "San Francisco, USA"
]

NORMAL_PROCESSES = [
    "explorer.exe", "svchost.exe", "chrome.exe", "msedge.exe",
    "slack.exe", "code.exe", "outlook.exe", "teams.exe", "notepad.exe"
]


class SyntheticDataService:
    """Deterministic synthetic data generator using fixed random seeds."""

    @staticmethod
    def compute_event_hash(ts: datetime, user: Optional[str], src: Optional[str], dst: Optional[str], etype: str, action: str) -> str:
        payload = f"{ts.isoformat()}|{user or ''}|{src or ''}|{dst or ''}|{etype}|{action}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    async def provision_assets(db: AsyncSession) -> None:
        """Seed 50 users, 30 devices, and 10 servers if not already present."""
        existing_assets = await db.execute(select(Asset).limit(1))
        if existing_assets.scalars().first():
            return

        assets_to_add = []

        # 1. 10 Servers (Tier-1 DB, Gateways, Tier-2 Apps)
        servers_spec = [
            ("SRV-DB-PRIMARY", "DATABASE", 100, "10.0.1.50", 1),
            ("SRV-DB-BACKUP", "DATABASE", 100, "10.0.1.51", 1),
            ("SRV-GW-EXT-01", "GATEWAY", 75, "10.0.0.1", 2),
            ("SRV-GW-INT-02", "GATEWAY", 75, "10.0.0.2", 2),
            ("SRV-APP-FINANCE", "SERVER", 75, "10.0.2.10", 2),
            ("SRV-APP-PORTAL", "SERVER", 75, "10.0.2.11", 2),
            ("SRV-AUTH-DC01", "SERVER", 100, "10.0.1.10", 1),
            ("SRV-AUTH-DC02", "SERVER", 100, "10.0.1.11", 1),
            ("SRV-FILE-NAS", "SERVER", 75, "10.0.3.5", 2),
            ("SRV-DEV-BUILD", "SERVER", 40, "10.0.4.20", 2),
        ]
        for name, atype, crit, ip, tier in servers_spec:
            assets_to_add.append(
                Asset(
                    asset_name=name,
                    asset_type=atype,
                    criticality_score=crit,
                    ip_address=ip,
                    metadata_json={"tier": tier, "role": atype, "environment": "SYNTHETIC_PROD"}
                )
            )

        # 2. 30 Devices
        for i in range(1, 31):
            dtype = "WORKSTATION" if i <= 20 else "LAPTOP"
            ip = f"192.168.1.{100 + i}"
            mac = f"00:50:56:A1:B2:{i:02X}"
            assets_to_add.append(
                Asset(
                    asset_name=f"DEV-WKS-{i:03d}",
                    asset_type=dtype,
                    criticality_score=40,
                    ip_address=ip,
                    mac_address=mac,
                    metadata_json={"os": "Windows 11 Enterprise", "department": "Operations"}
                )
            )

        db.add_all(assets_to_add)
        await db.commit()

    @staticmethod
    async def generate_normal_telemetry(
        db: AsyncSession,
        event_count: int = 500,
        seed: int = 42
    ) -> List[SecurityEvent]:
        """Generate baseline normal activity events across 50 users and 30 devices."""
        rng = random.Random(seed)
        await SyntheticDataService.provision_assets(db)

        users = [f"user_{i:02d}" for i in range(1, 51)]
        devices = [f"DEV-WKS-{i:03d}" for i in range(1, 31)]
        servers = ["SRV-DB-PRIMARY", "SRV-APP-FINANCE", "SRV-GW-EXT-01", "SRV-FILE-NAS"]

        now = datetime.now(timezone.utc)
        events = []

        for i in range(event_count):
            # Spread over 30 days
            offset_seconds = rng.randint(0, 30 * 86400)
            event_ts = now - timedelta(seconds=offset_seconds)

            # Weight active hours towards 8am-6pm (hours 8-18)
            hour = rng.choices(
                population=list(range(24)),
                weights=[1, 1, 1, 1, 1, 1, 2, 5, 10, 15, 15, 12, 10, 15, 15, 14, 10, 8, 4, 3, 2, 1, 1, 1]
            )[0]
            event_ts = event_ts.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59))

            user = rng.choice(users)
            user_idx = int(user.split("_")[1])
            assigned_dev = devices[(user_idx - 1) % len(devices)]
            loc = "New York, USA" if user_idx <= 35 else "London, UK"

            action_type = rng.choice(["AUTH", "NETWORK", "PROCESS", "DATA_TRANSFER"])

            if action_type == "AUTH":
                etype = "AUTHENTICATION"
                action = "USER_LOGIN"
                status = "SUCCESS"
                sev = "INFORMATIONAL"
                proc = "winlogon.exe"
                dvol = 0
                auth_m = rng.choice(["PASSWORD", "MFA", "KERBEROS"])
            elif action_type == "NETWORK":
                etype = "NETWORK_CONNECTION"
                action = "CONNECT_ESTABLISHED"
                status = "SUCCESS"
                sev = "INFORMATIONAL"
                proc = rng.choice(NORMAL_PROCESSES)
                dvol = rng.randint(1024, 100 * 1024)
                auth_m = "NONE"
            elif action_type == "PROCESS":
                etype = "PROCESS_EXECUTION"
                action = "PROCESS_SPAWN"
                status = "SUCCESS"
                sev = "INFORMATIONAL"
                proc = rng.choice(NORMAL_PROCESSES)
                dvol = 0
                auth_m = "NONE"
            else:
                etype = "DATA_TRANSFER"
                action = "OUTBOUND_TRANSFER"
                status = "SUCCESS"
                sev = "LOW"
                proc = "chrome.exe"
                dvol = rng.randint(10 * 1024, 5 * 1024 * 1024)  # 10KB to 5MB
                auth_m = "NONE"

            src_ip = f"192.168.1.{100 + (user_idx % 30) + 1}"
            dst_ip = f"10.0.{rng.randint(1, 3)}.{rng.randint(10, 50)}"

            ehash = SyntheticDataService.compute_event_hash(event_ts, user, src_ip, dst_ip, etype, action)

            ev = SecurityEvent(
                timestamp=event_ts,
                username=user,
                source_ip=src_ip,
                destination_ip=dst_ip,
                device_id=assigned_dev,
                device_name=f"WS-{user.upper()}",
                server_id=rng.choice(servers),
                event_type=etype,
                action=action,
                status=status,
                severity=sev,
                process_name=proc,
                data_volume=dvol,
                location=loc,
                authentication_method=auth_m,
                metadata_json={"synthetic": True, "dataset": "NORMAL_BASELINE"},
                event_hash=ehash
            )
            events.append(ev)

            # Update baseline in memory
            await UEBAService.update_baseline_with_event(db, {
                "username": user,
                "device_id": assigned_dev,
                "timestamp": event_ts,
                "location": loc,
                "process_name": proc,
                "data_volume": dvol
            })

        db.add_all(events)
        await db.commit()
        return events

    @staticmethod
    async def inject_brute_force_scenario(
        db: AsyncSession,
        target_user: str = "user_05",
        seed: int = 101
    ) -> List[SecurityEvent]:
        """Scenario 2: Brute force login sequence leading to suspicious execution and exfiltration."""
        rng = random.Random(seed)
        now = datetime.now(timezone.utc)
        src_ip = "198.51.100.42"  # External foreign attacker IP
        events = []

        # 1. Five failed logins within 3 minutes
        for i in range(5):
            ts = now - timedelta(minutes=15) + timedelta(seconds=i * 25)
            ehash = SyntheticDataService.compute_event_hash(ts, target_user, src_ip, "10.0.0.1", "AUTHENTICATION", "USER_LOGIN_FAILED")
            events.append(SecurityEvent(
                timestamp=ts,
                username=target_user,
                source_ip=src_ip,
                destination_ip="10.0.0.1",
                device_id="UNKNOWN-ATTACK-NODE",
                device_name="DESKTOP-ROGUE",
                server_id="SRV-GW-EXT-01",
                event_type="AUTHENTICATION",
                action="USER_LOGIN_FAILED",
                status="FAILURE",
                severity="LOW",
                process_name="ssh.exe",
                data_volume=0,
                location="Moscow, Russia",
                authentication_method="PASSWORD",
                metadata_json={"failure_reason": "BAD_CREDENTIALS", "scenario": "BRUTE_FORCE"},
                event_hash=ehash
            ))

        # 2. Successful login 45 seconds later
        succ_ts = now - timedelta(minutes=12)
        events.append(SecurityEvent(
            timestamp=succ_ts,
            username=target_user,
            source_ip=src_ip,
            destination_ip="10.0.0.1",
            device_id="UNKNOWN-ATTACK-NODE",
            device_name="DESKTOP-ROGUE",
            server_id="SRV-GW-EXT-01",
            event_type="AUTHENTICATION",
            action="USER_LOGIN_SUCCESS",
            status="SUCCESS",
            severity="CRITICAL",
            process_name="ssh.exe",
            data_volume=0,
            location="Moscow, Russia",
            authentication_method="PASSWORD",
            metadata_json={"scenario": "BRUTE_FORCE", "post_compromise": True},
            event_hash=SyntheticDataService.compute_event_hash(succ_ts, target_user, src_ip, "10.0.0.1", "AUTHENTICATION", "USER_LOGIN_SUCCESS")
        ))

        # 3. Suspicious process execution under the user account
        proc_ts = now - timedelta(minutes=10)
        events.append(SecurityEvent(
            timestamp=proc_ts,
            username=target_user,
            source_ip="10.0.0.1",
            destination_ip="10.0.2.10",
            device_id="UNKNOWN-ATTACK-NODE",
            server_id="SRV-APP-FINANCE",
            event_type="PROCESS_EXECUTION",
            action="PROCESS_SPAWN",
            status="SUCCESS",
            severity="HIGH",
            process_name="powershell.exe",
            data_volume=0,
            location="Moscow, Russia",
            authentication_method="NONE",
            metadata_json={"command_line": "powershell.exe -enc JAB3AGgAbwBhAG0AaQA...", "scenario": "SUSPICIOUS_PROCESS"},
            event_hash=SyntheticDataService.compute_event_hash(proc_ts, target_user, "10.0.0.1", "10.0.2.10", "PROCESS_EXECUTION", "PROCESS_SPAWN")
        ))

        # 4. Large outbound data transfer (85MB egress)
        exfil_ts = now - timedelta(minutes=8)
        events.append(SecurityEvent(
            timestamp=exfil_ts,
            username=target_user,
            source_ip="10.0.2.10",
            destination_ip="198.51.100.42",
            device_id="DEV-WKS-005",
            server_id="SRV-APP-FINANCE",
            event_type="DATA_TRANSFER",
            action="OUTBOUND_TRANSFER",
            status="SUCCESS",
            severity="HIGH",
            process_name="powershell.exe",
            data_volume=85 * 1024 * 1024,  # 85MB
            location="Moscow, Russia",
            authentication_method="NONE",
            metadata_json={"protocol": "HTTPS", "destination_port": 443, "scenario": "DATA_EXFILTRATION"},
            event_hash=SyntheticDataService.compute_event_hash(exfil_ts, target_user, "10.0.2.10", "198.51.100.42", "DATA_TRANSFER", "OUTBOUND_TRANSFER")
        ))

        db.add_all(events)
        await db.commit()
        return events

    @staticmethod
    async def inject_impossible_travel_scenario(
        db: AsyncSession,
        target_user: str = "user_02"
    ) -> List[SecurityEvent]:
        """Scenario 3: Impossible travel from New York to Tokyo within 12 minutes."""
        now = datetime.now(timezone.utc)
        events = []

        # 1. Normal login from New York
        t1 = now - timedelta(minutes=20)
        events.append(SecurityEvent(
            timestamp=t1,
            username=target_user,
            source_ip="192.168.1.102",
            destination_ip="10.0.0.1",
            device_id="DEV-WKS-002",
            device_name="WS-USER02",
            server_id="SRV-GW-EXT-01",
            event_type="AUTHENTICATION",
            action="USER_LOGIN",
            status="SUCCESS",
            severity="INFORMATIONAL",
            process_name="winlogon.exe",
            data_volume=0,
            location="New York, USA",
            authentication_method="MFA",
            metadata_json={"scenario": "IMPOSSIBLE_TRAVEL_LEG1"},
            event_hash=SyntheticDataService.compute_event_hash(t1, target_user, "192.168.1.102", "10.0.0.1", "AUTHENTICATION", "USER_LOGIN")
        ))

        # 2. Login from Tokyo 12 minutes later (distance > 10,800 km, velocity > 50,000 km/h)
        t2 = t1 + timedelta(minutes=12)
        events.append(SecurityEvent(
            timestamp=t2,
            username=target_user,
            source_ip="203.0.113.88",
            destination_ip="10.0.0.1",
            device_id="DEV-LAPTOP-ROGUE",
            device_name="LAPTOP-FOREIGN",
            server_id="SRV-GW-EXT-01",
            event_type="AUTHENTICATION",
            action="USER_LOGIN",
            status="SUCCESS",
            severity="HIGH",
            process_name="chrome.exe",
            data_volume=0,
            location="Tokyo, Japan",
            authentication_method="PASSWORD",
            metadata_json={"scenario": "IMPOSSIBLE_TRAVEL_LEG2"},
            event_hash=SyntheticDataService.compute_event_hash(t2, target_user, "203.0.113.88", "10.0.0.1", "AUTHENTICATION", "USER_LOGIN_TOKYO")
        ))

        db.add_all(events)
        await db.commit()
        return events

    @staticmethod
    async def reset_synthetic_data(db: AsyncSession) -> Dict[str, Any]:
        """Purge all synthetic events, batches, and baselines while preserving registered users."""
        await db.execute(delete(SecurityEvent))
        await db.execute(delete(IngestionBatch))
        await db.execute(delete(UEBABaseline))
        await db.commit()
        return {"status": "SUCCESS", "message": "Synthetic telemetry, batches, and baselines reset cleanly."}
