# Academic Positioning, Operational Guardrails, and Comprehensive Risk Analysis

> **Academic Prototype Designation**: Research Platform for Human-in-the-Loop Autonomous Cyber Incident Triage  
> **Canonical Positioning**:  
> *"An evidence-driven academic prototype integrating SIEM-style event ingestion, UEBA, anomaly detection, AI-assisted investigation, attack correlation, MITRE ATT&CK mapping, response simulation, human approval, and continuous learning into one coherent workflow."*

---

## 1. System Positioning and Safety Boundaries

### 1.1 Academic Scope & Explicit Prohibitions
To ensure ethical research practices and prevent operational misunderstandings in industrial or educational deployments, the platform establishes clear boundaries:
1. **No Claims of Absolute Security**: The platform makes no claim of 100% security, invulnerability to evasion, or complete detection coverage.
2. **Not a Commercial Replacement**: The platform is explicitly not a drop-in replacement for commercial Enterprise SIEM (Splunk, Microsoft Sentinel), XDR/EDR (CrowdStrike, SentinelOne), or SOAR (Palo Alto Cortex, Splunk SOAR) platforms. It is an experimental framework demonstrating evidence-grounded AI investigation, deterministic risk aggregation, and digital twin simulation.
3. **Safe Simulation Sandbox**: All response actions operate strictly in a software-emulated domain. The platform contains **zero integration hooks or system-level permissions** to alter host firewalls, modify Active Directory accounts, terminate operating system processes, isolate hardware NICs, or disrupt live network traffic.

### 1.2 Mandatory Taxonomy & Output Labelling Standards
To ensure analysts and observers can distinguish empirical fact from statistical inference, all outputs must carry standard taxonomy tags:

```
+-----------------------------------------------------------------------------------------------+
| TAXONOMY LABELS & OPERATIONAL SIGNIFICANCE                                                   |
+------------------------------------+----------------------------------------------------------+
| Label Marker                       | Operational Significance & Semantics                     |
+------------------------------------+----------------------------------------------------------+
| [SYNTHETIC DATA]                   | Deterministically generated test event or entity.         |
| [POTENTIAL ANOMALY]                | Statistical outlier identified by unsupervised ML.       |
| [ESTIMATED PREDICTION]             | Probabilistic forecast of blast radius or attack step.   |
| [SIMULATED ACTION]                 | Countermeasure applied only to in-memory Digital Twin.    |
| [INTERNAL EVALUATION METRIC]       | Locally calibrated research metric (e.g. Health Score).  |
+------------------------------------+----------------------------------------------------------+
```

---

## 2. Comprehensive Risk Analysis & Mitigation Matrix

### 2.1 Technical & Machine Learning Risks

| Risk Scenario | Severity | Potential Impact | Architectural Mitigation |
| :--- | :---: | :--- | :--- |
| **High False Positive Rate in Isolation Forest** | High | SOC analyst alert fatigue; loss of trust in anomaly indicators. | Isolation Forest outputs are strictly labeled `POTENTIAL ANOMALY` and weighted as only 25% of composite risk. Detections require corroborating deterministic rules or correlation before triggering critical alerts. |
| **Concept Drift in User Baselines** | Medium | Normal seasonal shifts or project changes flagged as anomalous. | Baselines use a 30-day rolling window with decay weights. Analysts can submit `FALSE_POSITIVE` feedback to recalibrate threshold margins without corrupting core data. |
| **Correlation Window Edge Cases** | Medium | Coordinated slow-and-low APT attacks spanning days split into disjoint incidents. | In addition to the 15-minute sliding active window, incidents support persistent multi-stage entity correlation chains that remain open until formal containment or resolution. |
| **Unsupervised Model Misinterpretation** | High | Analysts assuming ML output represents verified threat presence. | UI and API responses enforce the `POTENTIAL ANOMALY` label alongside explicit contributing feature values (e.g., *data transfer volume z-score = 3.4*). |

### 2.2 Cybersecurity & Abuse Risks

| Risk Scenario | Severity | Potential Impact | Architectural Mitigation |
| :--- | :---: | :--- | :--- |
| **Accidental Simulation Leakage** | Critical | Real-world network or host disruption caused by response bugs. | Absolute code-level isolation: the response engine lacks operating system network drivers, subprocess APIs, or external orchestration connectors. |
| **Prompt Injection into AI Copilot** | High | Adversary embeds injection strings inside event logs (`process_name` or `metadata`) to hijack AI summaries. | Schema-constrained database grounding: the Copilot queries structured fields only. Prompts enforce strict XML/JSON data isolation fences, rejecting natural-language instructions embedded inside log attributes. |
| **Unauthorized Model Promotion** | High | Compromised or poisoned model deployed, blinding detection. | Promotion requires explicit Security Admin authorization, dual-control validation, and an immutable cryptographic audit ledger entry. |
| **Audit Log Tampering** | Critical | Insider modifies historical incident triage records or response logs. | Hash-chained ledger ($H_n = \text{SHA256}(H_{n-1} \parallel \dots)$) with PostgreSQL sequential row locking (`SELECT FOR UPDATE`). Verification endpoint detects broken links or payload changes. |

### 2.3 Data Privacy & Confidentiality Risks

| Risk Scenario | Severity | Potential Impact | Architectural Mitigation |
| :--- | :---: | :--- | :--- |
| **Cleartext Credential Leakage in Logs** | Critical | Ingestion of raw events containing passwords or API tokens exposes credentials. | Architectural blacklist automatically strips keys matching `password`, `auth_token`, `private_key`, `secret_key` at ingestion boundary before persistence. |
| **PII Exposure to Low-Tier Viewers** | Medium | Unauthorized visibility into employee names, emails, or internal IP schemes. | Enforced RBAC data masking: `Viewer` role receives masked IPs (`192.168.***.***`) and usernames (`a***`), enforced at route serialization layer. |

### 2.4 Performance & Scalability Risks

| Risk Scenario | Severity | Potential Impact | Architectural Mitigation |
| :--- | :---: | :--- | :--- |
| **Ingestion Bottlenecks under Event Spikes** | Medium | API timeout or queue backup during bulk event upload. | Asynchronous bulk database insertions via SQLAlchemy Core, database connection pooling with `asyncpg`, and declarative monthly range partitioning on `security_events`. |
| **Graph Traversal Explosion in Digital Twin** | Medium | High CPU/memory latency during deep blast-radius calculations. | Breadth-First Search (BFS) capped at a maximum depth of 4 hops; in-memory caching of static network topology. |
| **Audit Row-Lock Contention** | Low | Write latency during high-frequency concurrent audit logging. | Audit writes batch non-critical metadata while strictly locking the hash chain anchor only during atomic state commits. |
