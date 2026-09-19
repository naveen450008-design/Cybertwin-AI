# REST API Specification & Contract Interface

> **Framework**: FastAPI (Python 3.11+)  
> **Data Validation**: Pydantic v2  
> **Security Scheme**: HTTP Bearer (JWT)  
> **Content Types**: `application/json`, `multipart/form-data`  
> **Standard Error Format**: RFC 7807 Problem Details

---

## 1. Authentication & Identity Endpoints

### 1.1 `POST /api/v1/auth/login`
- **Description**: Authenticate analyst credentials and issue signed JWT access and refresh tokens.
- **RBAC Requirement**: Public (Unauthenticated)
- **Request Body**:
  ```json
  {
    "username": "analyst_sarah",
    "password": "SecurePassword123!"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
      "token_type": "bearer",
      "expires_in": 3600,
      "user": {
        "user_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        "username": "analyst_sarah",
        "role": "Security Analyst",
        "full_name": "Sarah Connor"
      }
    }
    ```
  - `401 Unauthorized`: Invalid credentials.

### 1.2 `GET /api/v1/auth/me`
- **Description**: Return current authenticated session details and effective RBAC permissions.
- **RBAC Requirement**: Authenticated (Viewer, Incident Responder, Security Analyst, Security Admin)
- **Responses**:
  - `200 OK`:
    ```json
    {
      "user_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "username": "analyst_sarah",
      "role": "Security Analyst",
      "permissions": [
        "EVENTS_INGEST",
        "DEMO_TRIGGER",
        "INCIDENTS_VIEW_FULL",
        "INCIDENTS_UPDATE",
        "COPILOT_USE",
        "SIMULATION_APPROVE_HIGH",
        "AUDIT_VIEW"
      ]
    }
    ```

---

## 2. Event Ingestion Endpoints

### 2.1 `POST /api/v1/events/ingest`
- **Description**: Ingest a single security event or a batch array of canonical security events.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Request Body**:
  ```json
  [
    {
      "timestamp": "2026-09-19T04:12:00Z",
      "username": "alex.chen",
      "source_ip": "192.168.1.104",
      "destination_ip": "10.0.0.15",
      "device_id": "DEV-WKS-012",
      "device_name": "WS-FINANCE-CHEN",
      "server_id": "SRV-APP-002",
      "event_type": "AUTHENTICATION",
      "action": "USER_LOGIN",
      "status": "FAILURE",
      "severity": "LOW",
      "process_name": "winlogon.exe",
      "data_volume": 0,
      "location": "New York, USA",
      "authentication_method": "PASSWORD",
      "metadata": {
        "failure_reason": "BAD_PASSWORD",
        "workstation_domain": "CORP"
      }
    }
  ]
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "batch_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "total_received": 1,
      "valid_events": 1,
      "invalid_events": 0,
      "duplicate_events": 0,
      "stored_events": 1,
      "processing_status": "COMPLETED",
      "alerts_generated": 0,
      "incidents_affected": []
    }
    ```

### 2.2 `POST /api/v1/events/upload-csv`
- **Description**: Streamed upload of raw event CSV files with automatic header mapping and schema validation.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Request Body**: `multipart/form-data` with field `file: Binary`
- **Responses**:
  - `200 OK`: Ingestion telemetry summary (same schema as 2.1).

### 2.3 `POST /api/v1/events/upload-json`
- **Description**: Bulk upload of JSON array batch files.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Request Body**: `multipart/form-data` with field `file: Binary`
- **Responses**:
  - `200 OK`: Ingestion telemetry summary.

### 2.4 `GET /api/v1/events`
- **Description**: Query stored canonical security events with pagination and filtering.
- **RBAC Requirement**: All authenticated roles (Viewers receive masked usernames and IPs).
- **Query Parameters**:
  - `start_time`: ISO-8601 (optional)
  - `end_time`: ISO-8601 (optional)
  - `event_type`: Filter by enum (optional)
  - `severity`: Filter by severity (optional)
  - `limit`: Default 50, Max 500
  - `offset`: Default 0
- **Responses**:
  - `200 OK`: Array of events, total count, pagination tokens.

---

## 3. Synthetic Demo Environment Endpoints

All synthetic demo endpoints inject deterministic telemetry tagged visibly with `SYNTHETIC DATA`.

### 3.1 `POST /api/v1/demo/generate-normal`
- **Description**: Generates normal background telemetry across 50 users and 30 devices to refresh baseline models.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Request Body**:
  ```json
  {
    "event_count": 200,
    "seed": 42
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "status": "SUCCESS",
      "dataset_marker": "SYNTHETIC DATA",
      "events_created": 200,
      "scenarios_injected": ["NORMAL_BASELINE_ACTIVITY"]
    }
    ```

### 3.2 `POST /api/v1/demo/generate-suspicious`
- **Description**: Injects a single localized attack scenario (e.g., impossible travel or suspicious process).
- **RBAC Requirement**: Security Analyst, Security Admin
- **Request Body**:
  ```json
  {
    "scenario_type": "IMPOSSIBLE_TRAVEL",
    "target_username": "sarah.admin"
  }
  ```
- **Responses**:
  - `200 OK`: Scenario injection report with generated `event_ids` and created `incident_id`.

### 3.3 `POST /api/v1/demo/generate-coordinated-attack`
- **Description**: Injects a multi-stage correlated APT attack chain spanning brute force, execution, privilege escalation, and exfiltration.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Responses**:
  - `200 OK`: Attack sequence metadata, correlating incident details, and MITRE mapping summary.

### 3.4 `POST /api/v1/demo/run-full-simulation`
- **Description**: Deterministically provisions all 50 users, 30 devices, 10 servers, 30-day baseline telemetry, and 20 correlated incidents across all 6 scenarios.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Responses**:
  - `200 OK`:
    ```json
    {
      "status": "COMPLETED",
      "dataset_marker": "SYNTHETIC DATA",
      "total_events_seeded": 540,
      "incidents_created": 20,
      "baseline_profile_count": 80,
      "execution_time_ms": 1420
    }
    ```

### 3.5 `POST /api/v1/demo/reset`
- **Description**: Purges all synthetic demo events, incidents, and simulation states while preserving audit trails and user credentials.
- **RBAC Requirement**: Security Admin
- **Responses**:
  - `200 OK`: Purge confirmation status.

---

## 4. Incident Management & Investigation Endpoints

### 4.1 `GET /api/v1/incidents`
- **Description**: Query incidents with risk scoring, SLA status, and pagination.
- **RBAC Requirement**: Authenticated (Viewer receives masked identifiers).
- **Query Parameters**:
  - `status`: Filter by status enum
  - `severity`: Filter by severity enum
  - `min_risk`: Minimum risk score (0-100)
  - `sla_status`: `ON_TRACK`, `APPROACHING_BREACH`, `BREACHED`
  - `limit`: Default 20, Max 100
  - `offset`: Default 0
- **Responses**:
  - `200 OK`: List of incident summaries, score breakdowns, and metadata.

### 4.2 `GET /api/v1/incidents/{incident_id}`
- **Description**: Retrieve comprehensive incident details, including score breakdown, MITRE tactics, evidence events, and recommended response playbooks.
- **RBAC Requirement**: Incident Responder, Security Analyst, Security Admin (Full details); Viewer (Masked).
- **Responses**:
  - `200 OK`:
    ```json
    {
      "incident_id": "c4b31a89-21df-4b72-9a01-b8417c8be034",
      "title": "Coordinated Brute Force and Privilege Escalation",
      "status": "CONTAINMENT_RECOMMENDED",
      "severity": "CRITICAL",
      "risk_scoring": {
        "final_risk_score": 88.5,
        "anomaly_score": 82.0,
        "threat_severity_score": 100,
        "asset_criticality_score": 100,
        "identity_sensitivity_score": 75,
        "event_sequence_score": 70,
        "attack_stage_score": 80,
        "formula_weights": {
          "anomaly": 0.25,
          "severity": 0.20,
          "asset": 0.15,
          "identity": 0.15,
          "sequence": 0.15,
          "stage": 0.10
        }
      },
      "confidence_score": 92.0,
      "evidence_quality": "HIGH",
      "sla": {
        "created_at": "2026-09-19T04:10:00Z",
        "deadline": "2026-09-19T04:40:00Z",
        "minutes_remaining": 18,
        "sla_indicator": "AMBER"
      },
      "mitre_mappings": [
        {
          "technique_id": "T1110.001",
          "technique_name": "Password Guessing",
          "tactic": "Credential Access",
          "evidence_event_ids": ["8f029..."]
        }
      ],
      "evidence_events_count": 7
    }
    ```

### 4.3 `PATCH /api/v1/incidents/{incident_id}/status`
- **Description**: Update incident lifecycle status and append analyst notes.
- **RBAC Requirement**: Incident Responder, Security Analyst, Security Admin
- **Request Body**:
  ```json
  {
    "status": "CONTAINED",
    "notes": "Simulated isolation completed successfully in digital twin."
  }
  ```
- **Responses**:
  - `200 OK`: Updated incident record.

### 4.4 `GET /api/v1/incidents/{incident_id}/timeline`
- **Description**: Return chronologically ordered evidence events for the interactive timeline and replay scrubber.
- **RBAC Requirement**: Authenticated
- **Responses**:
  - `200 OK`: Array of timeline events with detection reasons and risk contribution.

### 4.5 `GET /api/v1/incidents/{incident_id}/graph`
- **Description**: Generate React Flow-compatible node and edge topology for the attack path.
- **RBAC Requirement**: Authenticated
- **Responses**:
  - `200 OK`:
    ```json
    {
      "nodes": [
        {"id": "usr-1", "type": "userNode", "data": {"label": "alex.chen", "role": "Privileged"}},
        {"id": "dev-1", "type": "deviceNode", "data": {"label": "WS-FINANCE-CHEN", "ip": "192.168.1.104"}},
        {"id": "srv-1", "type": "serverNode", "data": {"label": "SRV-DB-001", "tier": 1}}
      ],
      "edges": [
        {"id": "e1", "source": "usr-1", "target": "dev-1", "label": "logged_into"},
        {"id": "e2", "source": "dev-1", "target": "srv-1", "label": "connected_to"}
      ]
    }
    ```

### 4.6 `GET /api/v1/incidents/{incident_id}/similar`
- **Description**: Query top 3 historically similar incidents using cosine similarity over normalized feature vectors.
- **RBAC Requirement**: Authenticated
- **Responses**:
  - `200 OK`:
    ```json
    [
      {
        "incident_id": "11a22b33-...",
        "similarity_score": 0.94,
        "title": "Credential Spraying against Gateway",
        "previous_response_action": "SIMULATE_BLOCK_IP",
        "final_status": "RESOLVED",
        "analyst_notes": "Identified as external penetration test.",
        "lessons_learned": "Enforce MFA for external IP ranges."
      }
    ]
    ```

### 4.7 `POST /api/v1/incidents/{incident_id}/feedback`
- **Description**: Submit analyst ground-truth feedback for model governance and threshold tuning.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Request Body**:
  ```json
  {
    "label": "CONFIRMED_THREAT",
    "notes": "Verified malicious payload in PowerShell execution trace."
  }
  ```
- **Responses**:
  - `200 OK`: Feedback confirmation and audit reference.

---

## 5. AI Investigation Copilot Endpoints

### 5.1 `POST /api/v1/copilot/chat`
- **Description**: Evidence-grounded natural language investigation copilot.
- **RBAC Requirement**: All authenticated roles
- **Request Body**:
  ```json
  {
    "incident_id": "c4b31a89-21df-4b72-9a01-b8417c8be034",
    "question": "What evidence supports the brute-force finding?"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "answer": "Between 04:12:00Z and 04:14:30Z, 5 consecutive failed login attempts were recorded from source IP 192.168.1.104 targeting user alex.chen via PASSWORD authentication, followed immediately by a successful authentication at 04:15:10Z from the same IP.",
      "supporting_evidence_event_ids": ["8f029a1...", "8f029a2..."],
      "confidence": "HIGH",
      "model_backend": "DETERMINISTIC_SCHEMA_GROUNDED"
    }
    ```
  - *Zero Evidence Fallback Response*:
    ```json
    {
      "answer": "I don't have enough evidence in the available security data.",
      "supporting_evidence_event_ids": [],
      "confidence": "LOW",
      "model_backend": "DETERMINISTIC_SCHEMA_GROUNDED"
    }
    ```

---

## 6. Digital Twin & Blast-Radius Simulation Endpoints

### 6.1 `GET /api/v1/digital-twin/topology`
- **Description**: Retrieve active enterprise graph topology for blast radius modeling.
- **RBAC Requirement**: Authenticated
- **Responses**:
  - `200 OK`: Complete graph of users, devices, servers, and active sessions.

### 6.2 `POST /api/v1/simulation/simulate-response`
- **Description**: Perform non-destructive blast radius calculation for a proposed simulated mitigation action.
- **RBAC Requirement**: Incident Responder, Security Analyst, Security Admin
- **Request Body**:
  ```json
  {
    "incident_id": "c4b31a89-21df-4b72-9a01-b8417c8be034",
    "action_type": "SIMULATE_ISOLATE_DEVICE",
    "target_entity_type": "DEVICE",
    "target_entity_id": "DEV-WKS-012"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "action_type": "SIMULATE_ISOLATE_DEVICE",
      "simulation_marker": "SIMULATED ACTION",
      "direct_impact": {
        "severed_sessions_count": 2,
        "terminated_active_connections": 5
      },
      "downstream_impact": {
        "disrupted_services": ["INTERNAL_EXPENSE_APP"],
        "critical_services_affected": []
      },
      "risk_reduction_estimate": 78.5,
      "business_disruption_score": 25.0,
      "reversibility": "HIGH",
      "requires_approval": true,
      "required_role": "Security Analyst"
    }
    ```

### 6.3 `POST /api/v1/simulation/approve`
- **Description**: Submit human-in-the-loop approval or rejection for a simulated response.
- **RBAC Requirement**: Role-gated (Low impact: Responder+; High impact: Analyst+)
- **Request Body**:
  ```json
  {
    "action_id": "5e11d044-8df5-430c-9742-02409f583ec8",
    "decision": "APPROVED",
    "reason": "Containment verified safe via blast-radius analysis."
  }
  ```
- **Responses**:
  - `200 OK`: Approval confirmation, digital twin state update, and audit log reference.

---

## 7. Audit & Compliance Endpoints

### 7.1 `GET /api/v1/audit/logs`
- **Description**: Paginated query of the tamper-evident audit ledger.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Query Parameters**:
  - `actor`: Filter by username
  - `action`: Filter by action taken
  - `limit`: Default 50, Max 200
  - `offset`: Default 0
- **Responses**:
  - `200 OK`: Audit records with SHA-256 hashes and chained links.

### 7.2 `GET /api/v1/audit/verify`
- **Description**: Sequential verification of the cryptographic audit hash chain from the Genesis block to the current head.
- **RBAC Requirement**: Security Analyst, Security Admin
- **Responses**:
  - `200 OK` (Valid Ledger):
    ```json
    {
      "is_valid": true,
      "total_records_verified": 348,
      "broken_chains_count": 0,
      "corrupted_records": [],
      "genesis_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "latest_hash": "8a719d3f10ec4bb523c914b4de..."
    }
    ```
  - `200 OK` (Tampering Detected):
    ```json
    {
      "is_valid": false,
      "total_records_verified": 348,
      "broken_chains_count": 1,
      "corrupted_records": [
        {
          "ledger_index": 142,
          "expected_hash": "4b10fa...",
          "actual_hash": "9c88be...",
          "tampered_field": "new_state_json"
        }
      ]
    }
    ```

---

## 8. Analytics & SLA Monitoring Endpoints

### 8.1 `GET /api/v1/analytics/dashboard`
- **Description**: Comprehensive SOC metric bundle: event totals, active incidents, MTTD, MTTR, and severity distribution.
- **RBAC Requirement**: Authenticated
- **Responses**:
  - `200 OK`: Metrics dashboard payload.

### 8.2 `GET /api/v1/analytics/security-health`
- **Description**: Tenant-level posture index with explicit academic classification.
- **RBAC Requirement**: Authenticated
- **Responses**:
  - `200 OK`:
    ```json
    {
      "security_health_score": 74.2,
      "classification": "INTERNAL EVALUATION METRIC - NON-INDUSTRY STANDARD",
      "components": {
        "identity_risk": 22.0,
        "endpoint_posture": 18.5,
        "network_exposure": 31.0,
        "unresolved_incident_severity": 45.0,
        "mean_containment_velocity": 85.0
      }
    }
    ```

---

## 9. Model Governance Endpoints

### 9.1 `GET /api/v1/models`
- **Description**: List registered ML models, performance metrics (Precision, Recall, F1), and deployment status.
- **RBAC Requirement**: Security Admin
- **Responses**:
  - `200 OK`: Model version history.

### 9.2 `POST /api/v1/models/retrain`
- **Description**: Trigger offline baseline re-training using collected normal telemetry and analyst labels.
- **RBAC Requirement**: Security Admin
- **Responses**:
  - `202 Accepted`: Job ID and training metrics summary.

### 9.3 `POST /api/v1/models/{version_id}/deploy`
- **Description**: Promote a validated model version to the active scoring engine.
- **RBAC Requirement**: Security Admin
- **Responses**:
  - `200 OK`: Model activation confirmation.
