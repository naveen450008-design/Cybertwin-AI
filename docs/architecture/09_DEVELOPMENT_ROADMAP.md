# Phased Development Roadmap & Acceptance Gates

> **Development Standard**: Sequential Phased Execution with Strict Verification Gates  
> **Rule**: No functional progression to a subsequent phase until all acceptance criteria and verification tests for the active phase pass with zero known errors.

---

## 1. Roadmap Overview & Phased Progression

```
+--------------------------------------------------------------------------------------------------+
| PHASE 0: System Architecture & Specification                                                     |
| Deliverables: Complete 9 Architectural Blueprints in docs/architecture/                         |
+--------------------------------------------------------------------------------------------------+
                                                 | (Explicit User Authorization Gate)
                                                 v
+--------------------------------------------------------------------------------------------------+
| PHASE 1: Core Ingestion, Database Setup, and Synthetic Data Engine                              |
| Deliverables: PostgreSQL Migrations, Canonical Ingestion API, 50-User/30-Device Demo Generator   |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
+--------------------------------------------------------------------------------------------------+
| PHASE 2: UEBA Baseline Modeling, Detection Rules, and Correlation Pipeline                       |
| Deliverables: 10 Detection Rules, 30-Day Baseline Engine, Isolation Forest, 15-min Correlator   |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
+--------------------------------------------------------------------------------------------------+
| PHASE 3: Transparent Risk Engine, MITRE ATT&CK Mapping, and Incident Management                  |
| Deliverables: 6-Factor Risk Score, Offline ATT&CK DB, Incident Lifecycle State Machine, SLA Track|
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
+--------------------------------------------------------------------------------------------------+
| PHASE 4: Digital Twin State Model, Blast Radius Simulation, and Safe Response Gate               |
| Deliverables: In-Memory Dependency Graph, Blast-Radius Calculator, Human Approval Workflow      |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
+--------------------------------------------------------------------------------------------------+
| PHASE 5: Tamper-Evident Audit Ledger, Strict RBAC, and Privacy Masking Engine                    |
| Deliverables: SHA-256 Hash-Chained Ledger, Sequential Row Locking, Verification API, RBAC Filter|
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
+--------------------------------------------------------------------------------------------------+
| PHASE 6: Grounded AI Investigation Copilot, Similar Incident Search, and Model Governance        |
| Deliverables: LLMProviderInterface, Schema-Grounded Synthesis, Cosine Similarity, F1 Tracking   |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
+--------------------------------------------------------------------------------------------------+
| PHASE 7: React Dark SOC Frontend, React Flow Attack Graph, and Timeline Replay Engine            |
| Deliverables: Vite React 18+ App, React Flow Graph, 1x/2x/5x Replay Scrubber, SLA Timers        |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
+--------------------------------------------------------------------------------------------------+
| PHASE 8: End-to-End Scenario Verification, Security Audit, and Final Delivery                    |
| Deliverables: 6 Attack Scenarios Tested, Integrity Verification, Performance Benchmark, Release  |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Detailed Phase Specifications

### Phase 0: System Architecture & Specification (CURRENT PHASE)
- **Scope**: Establish architectural blueprints, database schema, API contracts, frontend design, ML/UEBA specifications, RBAC/audit models, safety boundaries, risk matrix, and phased delivery plan.
- **Key Deliverables**:
  - `docs/architecture/01_SYSTEM_ARCHITECTURE.md`
  - `docs/architecture/02_DATABASE_SCHEMA.md`
  - `docs/architecture/03_API_SPECIFICATION.md`
  - `docs/architecture/04_FRONTEND_STRUCTURE.md`
  - `docs/architecture/05_AI_ML_UEBA_DESIGN.md`
  - `docs/architecture/06_SECURITY_RBAC_AUDIT.md`
  - `docs/architecture/07_DIGITAL_TWIN_SIMULATION.md`
  - `docs/architecture/08_RESEARCH_POSITIONING_RISKS.md`
  - `docs/architecture/09_DEVELOPMENT_ROADMAP.md`
- **Acceptance Criteria**: All 9 documents created, thoroughly cross-referenced, and reviewed against master safety constraints.
- **Delivery Gate**: Output summary report and halt execution awaiting explicit user authorization.

---

### Phase 1: Core Ingestion, Database Setup, and Synthetic Data Engine
- **Scope**: Initialize project repository structure, PostgreSQL database schemas, Alembic migrations, Pydantic canonical event models, ingestion APIs, and deterministic synthetic data generator.
- **Key Deliverables**:
  - `backend/` FastAPI project with async SQLAlchemy 2.0 and Alembic.
  - Canonical event ingestion endpoints: `/api/v1/events/ingest`, `/upload-csv`, `/upload-json`.
  - Synthetic demo engine: 50 users, 30 devices, 10 servers, 500+ events, pre-seeded 30-day normal baseline telemetry.
  - Endpoints: `POST /api/v1/demo/generate-normal`, `POST /api/v1/demo/generate-coordinated-attack`, `POST /api/v1/demo/reset`.
- **Acceptance Criteria**:
  - Ingesting a 100-event batch completes with accurate `stored_events` and validation telemetry.
  - Synthetic data generation reproduces identical deterministic event sets across repeated runs with seed 42.
  - All synthetic responses clearly include the marker `SYNTHETIC DATA`.

---

### Phase 2: UEBA Baseline Modeling, Detection Rules, and Correlation Pipeline
- **Scope**: Implement 30-day rolling baseline calculations, 10 deterministic detection rules, unsupervised Isolation Forest anomaly detection, and the 15-minute sliding correlation window.
- **Key Deliverables**:
  - UEBA baseline calculator profiling active hours, devices, locations, and data volume.
  - 10 deterministic rules (Brute-Force, Impossible Travel, Suspicious Process, Lateral Movement, etc.).
  - Scikit-learn Isolation Forest model scoring normalized 10-dimensional feature vectors.
  - Correlation Service clustering related events by entity and causal chain into unified incidents.
- **Acceptance Criteria**:
  - Impossible travel sequence (NY to Tokyo in 12 min) automatically triggers `RULE-GEO-001`.
  - 5 failed logins followed by a success generates a single correlated incident in status `NEW`.
  - Isolation Forest model flags statistical outliers with `POTENTIAL ANOMALY` and feature contribution breakdown.

---

### Phase 3: Transparent Risk Engine, MITRE ATT&CK Mapping, and Incident Management
- **Scope**: Implement the deterministic 6-factor risk scoring formula, offline MITRE ATT&CK mapping database, incident lifecycle management, and SLA tracking.
- **Key Deliverables**:
  - Risk engine calculating exact composite score (0-100) using normalized formula.
  - Offline MITRE ATT&CK catalog mapping techniques to supporting `event_id` evidence.
  - Incident status state machine (`NEW` $\to$ `INVESTIGATING` $\to$ `CONTAINMENT_RECOMMENDED` $\to$ `RESOLVED`).
  - Configurable SLA breach countdown timer with Green / Amber / Red threshold logic.
- **Acceptance Criteria**:
  - Incident risk score matches the exact formula:
    $$\min\left(100, 0.25 S_{\text{anomaly}} + 0.20 S_{\text{severity}} + 0.15 S_{\text{asset}} + 0.15 S_{\text{identity}} + 0.15 S_{\text{sequence}} + 0.10 S_{\text{stage}}\right)$$
  - Multi-tactic techniques (e.g., T1078 Valid Accounts) map correctly to tactic stages based on evidence.

---

### Phase 4: Digital Twin State Model, Blast Radius Simulation, and Safe Response Gate
- **Scope**: Build in-memory topological dependency graph, blast-radius calculation engine, and safe response simulation with human approval gates.
- **Key Deliverables**:
  - In-memory graph model representing Users, Sessions, Devices, Servers, Services, and Connections.
  - Simulated actions: `SIMULATE_BLOCK_IP`, `SIMULATE_ISOLATE_DEVICE`, `SIMULATE_TERMINATE_SESSION`, etc.
  - Blast-radius traversal algorithm computing affected user sessions, disrupted services, and business disruption score.
  - Human approval gate supporting `OBSERVE`, `RECOMMEND`, and `CONTROLLED_AUTONOMOUS` modes.
- **Acceptance Criteria**:
  - Zero operating system or network changes occur.
  - Simulating device isolation identifies all severed active user sessions and downstream dependent services.
  - High-impact actions (`SIMULATE_ISOLATE_DEVICE`) require approval from Security Analyst or Admin.

---

### Phase 5: Tamper-Evident Audit Ledger, Strict RBAC, and Privacy Masking Engine
- **Scope**: Implement SHA-256 hash-chained audit ledger with sequential database row locking, verification endpoint, RBAC matrix, and PII masking.
- **Key Deliverables**:
  - Audit logging service with atomic sequential locking (`SELECT FOR UPDATE`) to prevent forks.
  - Cryptographic verification endpoint: `GET /api/v1/audit/verify`.
  - RBAC middleware enforcing 4 roles across routes and services.
  - Privacy redaction filter masking IPs and usernames for Viewers.
- **Acceptance Criteria**:
  - Tampering with a database audit record is immediately flagged by `verify` with the exact record index.
  - Concurrent audit writes generate an unbroken sequential hash chain.
  - Viewer role queries return masked IPs (`192.168.***.***`) and redacted usernames.

---

### Phase 6: Grounded AI Investigation Copilot, Similar Incident Search, and Model Governance
- **Scope**: Implement `LLMProviderInterface`, database-grounded query synthesis, cosine similarity incident search, and model retraining governance.
- **Key Deliverables**:
  - AI Copilot answering 9 core investigation queries grounded strictly in database evidence.
  - Deterministic fallback output when no LLM is configured.
  - Fixed fallback string: *"I don't have enough evidence in the available security data."*
  - Similar incident search engine returning top 3 matching historical incidents.
  - Model governance dashboard tracking Precision, Recall, and F1, with Admin deployment approval.
- **Acceptance Criteria**:
  - Querying non-existent entities returns the exact required fallback string.
  - Retrained model artifacts require explicit Security Admin approval before activation.

---

### Phase 7: React Dark SOC Frontend, React Flow Attack Graph, and Timeline Replay Engine
- **Scope**: Build modern, responsive, high-density dark SOC user interface with interactive React Flow attack graph, timeline replay engine, and dashboard analytics.
- **Key Deliverables**:
  - React 18+ Vite TypeScript frontend with Tailwind CSS dark theme.
  - Interactive React Flow attack graph with custom nodes (User, Device, Server, IP, Process, Incident).
  - Chronological timeline scrubber with Play (1x, 2x, 5x), Pause, and Step Forward/Back controls.
  - Executive SOC dashboard with SLA countdowns and Security Health Score.
  - AI Copilot slide-out drawer and Digital Twin blast-radius modal.
- **Acceptance Criteria**:
  - Replay controls step through attack events, highlighting active nodes on the graph synchronously.
  - Visual badges display required taxonomy (`SYNTHETIC DATA`, `POTENTIAL ANOMALY`, etc.).

---

### Phase 8: End-to-End Scenario Verification, Security Audit, and Final Delivery
- **Scope**: Full system integration testing across all 6 attack scenarios, security boundary audit, end-to-end verification walkthrough, and documentation finalization.
- **Key Deliverables**:
  - Automated integration test suite validating the complete pipeline from ingestion to response.
  - Demonstration walk-through covering all 6 core scenarios.
  - Finalized system documentation and operational user manual.
- **Acceptance Criteria**:
  - All 6 attack scenarios execute reliably and deterministically.
  - Zero security boundary violations or cleartext credential leaks detected in logs.
