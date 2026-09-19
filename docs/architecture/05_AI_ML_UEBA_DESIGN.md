# AI, Machine Learning, UEBA, and Detection Engine Specification

> **Classification**: Dual-Engine Analytical Pipeline (Deterministic Rule Engine + Unsupervised Machine Learning + Database-Grounded AI Copilot)  
> **Mandatory Output Markers**: `POTENTIAL ANOMALY`, `ESTIMATED PREDICTION`, `INTERNAL EVALUATION METRIC`

---

## 1. Deterministic Detection Rules

The deterministic rule engine evaluates incoming normalized security events against static threshold heuristics and spatial-temporal constraints:

| Rule Identifier | Trigger Criteria | Evaluated Entities | Output Severity | MITRE Technique |
| :--- | :--- | :--- | :--- | :--- |
| `RULE-AUTH-001` | $\ge 5$ failed authentications within 5 minutes | `username` OR `source_ip` | HIGH | T1110.001 (Password Guessing) |
| `RULE-AUTH-002` | Successful authentication within 3 minutes following `RULE-AUTH-001` | `username` AND `source_ip` | CRITICAL | T1078 (Valid Accounts) |
| `RULE-GEO-001` | Calculated velocity $> 1000\text{ km/h}$ between successive authentications | `username` | HIGH | T1078 (Valid Accounts) |
| `RULE-UEBA-001` | Authentication from a device not present in user's known device baseline | `username`, `device_id` | MEDIUM | T1078 (Valid Accounts) |
| `RULE-UEBA-002` | Authentication from a location not present in user's known location baseline | `username`, `location` | MEDIUM | T1078 (Valid Accounts) |
| `RULE-UEBA-003` | Authentication occurring outside user's active baseline hours ($\pm 2\text{ hours}$) | `username`, `timestamp` | LOW | T1078 (Valid Accounts) |
| `RULE-PROC-001` | Execution of anomalous binaries (`powershell.exe`, `cmd.exe`, `certutil.exe`, `whoami.exe`) under a standard user account | `process_name`, `username` | HIGH | T1059.001 (PowerShell) |
| `RULE-NET-001` | Outbound data transfer exceeding $3\times$ user's baseline standard deviation and $> 50\text{ MB}$ | `username`, `data_volume` | HIGH | T1048 (Exfiltration Over Alt Protocol) |
| `RULE-NET-002` | Connection frequency exceeding $5\times$ rolling average in 1-minute window | `source_ip`, `device_id` | MEDIUM | T1046 (Network Service Discovery) |
| `RULE-CHAIN-001` | Correlated sequence: Brute Force $\to$ Success $\to$ Suspicious Process $\to$ High Egress | Cross-entity chain | CRITICAL | Multi-Tactic Campaign |

### 1.1 Impossible-Travel Velocity Calculation
The geospatial speed between consecutive authentications for a user is determined using the Great-Circle Haversine formula:

$$d = 2R \arcsin \left( \sqrt{\sin^2\left(\frac{\Delta \phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta \lambda}{2}\right)} \right)$$

$$\text{Velocity} = \frac{d}{\Delta t} \quad [\text{km/h}]$$

Where $R = 6371\text{ km}$. If $\text{Velocity} > 1000\text{ km/h}$ and $\Delta t < 24\text{ hours}$, `RULE-GEO-001` triggers immediately.

---

## 2. User and Entity Behaviour Analytics (UEBA)

### 2.1 Baseline Profiling
Every user and device entity maintains an active statistical baseline calculated over a rolling 30-day window:
- **Active Hours Profile**: A 24-bin normalized histogram recording the historical probability of authentication during each hour of the day (UTC).
- **Known Device Catalog**: Set of unique `device_id` values used successfully by the identity.
- **Usual Locations / Subnets**: Set of recognized geolocations, CIDR blocks, and source IP clusters.
- **Process Allow-list**: Historically observed process hashes and executable names executed in the context of the identity.
- **Egress Volume Statistics**: Running mean ($\mu$) and standard deviation ($\sigma$) of outbound bytes transferred per session.
- **Connection Frequency**: Mean count of network socket establishments per hour.

---

## 3. Unsupervised ML Anomaly Detection: Isolation Forest

To uncover zero-day anomalies and multi-variable stealth tactics that evade static threshold rules, the engine incorporates an unsupervised **Isolation Forest** model from `scikit-learn`.

### 3.1 10-Dimensional Feature Vector
Each event and associated entity state is projected into a normalized 10-dimensional numerical vector $\vec{x} \in \mathbb{R}^{10}$:

```python
feature_vector = [
    failed_login_count,          # Count of failures in preceding 15-minute window
    successful_login_count,      # Count of successes in preceding 15-minute window
    login_frequency,             # Authentications per minute over trailing 1 hour
    time_of_day_deviation,       # Distance from nearest peak in active-hours baseline [0.0 - 1.0]
    new_device_indicator,        # 1.0 if device is unknown in baseline, else 0.0
    new_location_indicator,      # 1.0 if location is unknown in baseline, else 0.0
    data_transfer_volume,        # Standardized z-score of transferred bytes: (V - mean) / stddev
    process_novelty_score,       # 1.0 if binary unseen in user history, 0.5 if rare, 0.0 if normal
    event_frequency,             # Aggregate event count in trailing 5-minute window
    connection_frequency         # Outbound socket connections in trailing 5-minute window
]
```

### 3.2 Anomaly Scoring & Output Format
- **Raw Decision Score**: $s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$, where $E(h(x))$ is the average path length across isolation trees.
- **Normalized Anomaly Score ($S_{\text{anomaly}}$)**: Scaled strictly to $[0, 100]$:
  $$S_{\text{anomaly}} = \text{clip}\left(\frac{s - s_{\min}}{s_{\max} - s_{\min}} \times 100, 0, 100\right)$$
- **Evidence Quality Rating**:
  - `HIGH`: $\ge 3$ features exhibit extreme deviation ($z > 3.0$ or binary novelties $= 1.0$) with detection confidence $\ge 80\%$.
  - `MEDIUM`: $1 - 2$ features deviate with detection confidence between $50\%$ and $79\%$.
  - `LOW`: Subtle statistical outlier with detection confidence $< 50\%$.
- **Mandatory Display Marker**: All model-generated detections are strictly annotated with `POTENTIAL ANOMALY`.

---

## 4. Alert Deduplication and Event Correlation

To eliminate alert fatigue, the platform aggregates disparate rule triggers and anomalies into single, contextual security incidents.

### 4.1 15-Minute Sliding Correlation Window
1. When an alert fires at $T_0$, the correlation engine searches for an active, uncontained incident involving the same `username`, `device_id`, or `source_ip` within $[T_0 - 15\text{ mins}, T_0]$.
2. If a matching incident exists, the new alert and its raw supporting event are appended to the existing incident's evidence ledger, updating its severity and risk scores.
3. If no matching incident exists, a new incident entity is created in state `NEW`.

### 4.2 Multi-Stage Attack Correlation
The state machine correlates multi-step event sequences:
$$\text{Failed Login} \xrightarrow{\text{5x in 5m}} \text{Successful Login} \xrightarrow{\text{new device}} \text{PowerShell Execution} \xrightarrow{\text{privilege change}} \text{Data Transfer}$$
This sequence is clustered into **one cohesive incident**, preventing the creation of six fragmented tickets.

### 4.3 Incident Lifecycle States
```text
NEW ──> INVESTIGATING ──> CONTAINMENT_RECOMMENDED ──> RESPONSE_PENDING
                                                            │
    ┌───────────────────────┬───────────────────────────────┤
    ▼                       ▼                               ▼
CONTAINED               RESOLVED                      FALSE_POSITIVE
    │                       │                               │
    └───────────────────────┴───────────────────────────────┴──> CLOSED
```

---

## 5. Transparent Risk, Confidence, and Security Health Scoring

### 5.1 Deterministic Composite Risk Score Formula
The platform forbids opaque or black-box risk evaluations. The composite score is calculated using six normalized parameters:

$$\text{Risk Score} = \min\left(100, 0.25 S_{\text{anomaly}} + 0.20 S_{\text{severity}} + 0.15 S_{\text{asset}} + 0.15 S_{\text{identity}} + 0.15 S_{\text{sequence}} + 0.10 S_{\text{stage}}\right)$$

#### Parameter Calibrations:
1. **Anomaly Score ($S_{\text{anomaly}}$)**: Continuous normalized output from Isolation Forest $\in [0, 100]$.
2. **Threat Severity Score ($S_{\text{severity}}$)**:
   - `CRITICAL` = 100
   - `HIGH` = 75
   - `MEDIUM` = 50
   - `LOW` = 25
   - `INFORMATIONAL` = 10
3. **Asset Criticality Score ($S_{\text{asset}}$)**:
   - Tier-1 Server or Critical Database = 100
   - Tier-2 Server or Application Gateway = 75
   - Standard Employee Workstation / Laptop = 40
4. **Identity Sensitivity Score ($S_{\text{identity}}$)**:
   - Domain Administrator or Executive = 100
   - Privileged User (DBA, DevOps, SecOps) = 75
   - Standard End-User = 50
5. **Event Sequence Score ($S_{\text{sequence}}$)**:
   $$S_{\text{sequence}} = \min\left(100, \frac{\text{event\_count}}{10} \times 100\right)$$
6. **Attack Stage Score ($S_{\text{stage}}$)**:
   - Initial Access = 30
   - Execution = 50
   - Privilege Escalation = 70
   - Lateral Movement = 80
   - Exfiltration or Impact = 100

### 5.2 Security Health Score
The tenant-level health metric is computed as a weighted balance of enterprise exposure:
$$\text{Health Score} = 100 - \left(0.25 I_{\text{risk}} + 0.20 E_{\text{posture}} + 0.20 N_{\text{exposure}} + 0.20 S_{\text{unresolved}} + 0.15 (100 - V_{\text{containment}})\right)$$

> **Mandatory Regulatory Banner**:  
> `INTERNAL EVALUATION METRIC - NON-INDUSTRY STANDARD`

---

## 6. MITRE ATT&CK Framework Mapping

An offline, curated knowledge repository links events directly to ATT&CK tactics and techniques based on observed evidence:

```json
[
  {
    "technique_id": "T1110.001",
    "technique_name": "Password Guessing",
    "tactics": ["Credential Access"],
    "rule_trigger": "RULE-AUTH-001",
    "confidence": 95.0
  },
  {
    "technique_id": "T1078",
    "technique_name": "Valid Accounts",
    "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
    "rule_trigger": "RULE-AUTH-002",
    "confidence": 90.0
  },
  {
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "tactics": ["Execution"],
    "rule_trigger": "RULE-PROC-001",
    "confidence": 98.0
  },
  {
    "technique_id": "T1048",
    "technique_name": "Exfiltration Over Alternative Protocol",
    "tactics": ["Exfiltration"],
    "rule_trigger": "RULE-NET-001",
    "confidence": 88.0
  }
]
```

---

## 7. AI Investigation Copilot Architecture

### 7.1 Abstracted Contract Interface
```python
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class LLMProviderInterface(ABC):
    @abstractmethod
    async def generate_response(
        self,
        prompt: str,
        context: Dict[str, Any],
        evidence_events: List[Dict[str, Any]]
    ) -> str:
        """Ground the response strictly in database context and evidence."""
        pass
```

### 7.2 Database-Grounded Fallback Engine
When no external provider is configured, the Copilot executes deterministic template synthesis directly over SQL query results. If a user queries details for which no matching evidence exists in the database, the engine returns the required standard text:
```text
I don't have enough evidence in the available security data.
```

---

## 8. Similar Incident Search Engine

The engine identifies past historical incidents using **Cosine Similarity** across a 6-dimensional normalized incident vector:

$$\vec{v} = \begin{bmatrix}
\text{Normalized Anomaly Score} \\
\text{Threat Severity Weight} \\
\text{Asset Criticality Score} \\
\text{Sequence Length Factor} \\
\text{MITRE Technique Overlap Jaccard Index} \\
\text{Response Outcome Code}
\end{bmatrix}$$

$$\text{Similarity}(\vec{u}, \vec{v}) = \frac{\vec{u} \cdot \vec{v}}{\|\vec{u}\| \|\vec{v}\|}$$

The top 3 incidents with $\text{Similarity} \ge 0.70$ are returned along with previous response outcomes and lessons learned.

---

## 9. Model Governance & Continuous Learning

1. **Analyst Feedback Intake**: Analysts classify incidents as `CONFIRMED_THREAT`, `FALSE_POSITIVE`, or `NEEDS_REVIEW`.
2. **Supervised Metric Tracking**: Ground-truth labels are compared against Isolation Forest detections to calculate real-world Precision, Recall, and F1:
   $$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}, \quad F1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
3. **No Direct Unsupervised Retraining**: Analyst labels do not directly retrain Isolation Forest as a supervised classifier. Instead, verified normal records update baseline distributions, and labeled datasets are archived for future supervised classification benchmarking.
4. **Security Admin Approval Gate**: A new model cannot be deployed to production scoring without an explicit Security Admin signature in the audit trail.
