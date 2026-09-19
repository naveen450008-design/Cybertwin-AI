# Frontend Architecture & Serious Dark SOC Design System

> **Framework**: React 18+ (Vite, TypeScript)  
> **Styling**: Tailwind CSS (Curated Dark SOC Palette)  
> **State Management**: TanStack Query (Server State) + Zustand (Local Replay & UI State)  
> **Graph Visualization**: React Flow  
> **Telemetry Charts**: Recharts  
> **Iconography**: Lucide React

---

## 1. Design Philosophy: Serious Dark SOC Interface

The user interface adopts a high-density, mission-critical Security Operations Center aesthetic designed for clarity during high-stress triage, avoiding generic palettes and frivolous styling.

### 1.1 Palette & Visual Tokens
- **Background Foundations**:
  - Main App Background: `#0B0F17` (Deep Obsidian Void)
  - Surface & Panel Background: `#111827` (Zinc Dark Slate)
  - Elevated Card Background: `#1F2937` with subtle `rgba(255, 255, 255, 0.05)` border stroke
  - Glassmorphic Modals: `backdrop-blur-md bg-opacity-80 bg-gray-900/90`
- **Functional Severity & Status Accents**:
  - `CRITICAL` / `SLA BREACH`: `#EF4444` (Vibrant Crimson Red)
  - `HIGH` / `SLA WARNING`: `#F97316` (Amber Flare Orange)
  - `MEDIUM` / `POTENTIAL ANOMALY`: `#EAB308` (Cyber Yellow)
  - `LOW` / `INFORMATIONAL`: `#3B82F6` (Electric Azure Blue)
  - `SUCCESS` / `CONTAINED`: `#10B981` (Emerald Shield Green)
  - `SYNTHETIC DATA` Badge: `#8B5CF6` (Neon Purple Pill Badge)
- **Typography Hierarchy**:
  - Primary UI & Data Tables: `Inter`, sans-serif (Clean legibility, tight tabular spacing)
  - Hashes, IP Addresses, CLI, Process Names, Timestamps: `JetBrains Mono`, monospace

---

## 2. Directory & Component Hierarchy

```text
frontend/src/
├── app/
│   ├── App.tsx                      # Root Application, Providers, Router setup
│   ├── main.tsx                     # Vite mounting point
│   └── routes.tsx                   # React Router v6 route configuration
├── assets/                          # Static logos, MITRE icon vectors
├── components/
│   ├── common/
│   │   ├── Header.tsx               # Top navigation, active user role pill, SOC health
│   │   ├── Sidebar.tsx              # Primary module navigation
│   │   ├── StatCard.tsx             # Metric card with delta indicators
│   │   ├── SeverityBadge.tsx        # Normalized severity and taxonomy pill labels
│   │   ├── SlaTimer.tsx             # Real-time incident SLA countdown (Green/Amber/Red)
│   │   └── Modal.tsx                # Accessible glassmorphism dialog
│   ├── attack-graph/
│   │   ├── AttackGraphView.tsx      # React Flow canvas wrapper with zoom/pan controls
│   │   ├── nodes/                   # Custom React Flow Nodes
│   │   │   ├── UserNode.tsx         # User entity node with privilege tier badge
│   │   │   ├── DeviceNode.tsx       # Workstation/device node with OS icon
│   │   │   ├── ServerNode.tsx       # Server node with Tier-1/Tier-2 indicator
│   │   │   ├── IpNode.tsx           # Public/Private IP address node
│   │   │   ├── ProcessNode.tsx      # Process execution node with hash
│   │   │   └── IncidentNode.tsx     # Central incident focal node with risk score
│   │   └── edges/
│   │   │   ├── CustomEdge.tsx       # Animated directional edge with action labels
│   │   │   └── EdgeLabelRenderer.tsx
│   ├── timeline/
│   │   ├── IncidentTimeline.tsx     # Vertical chronological event trace
│   │   ├── TimelineItem.tsx         # Event details card with raw metadata viewer
│   │   └── ReplayControls.tsx       # Play (1x, 2x, 5x), Pause, Step, Scrubber bar
│   ├── digital-twin/
│   │   ├── TopologyVisualizer.tsx   # In-memory twin state view
│   │   ├── BlastRadiusModal.tsx     # Direct and downstream impact analysis breakdown
│   │   └── ApprovalActionCard.tsx   # Human approval action form with dual-control gate
│   ├── copilot/
│   │   ├── CopilotDrawer.tsx        # Slide-out AI investigation assistant panel
│   │   ├── MessageList.tsx          # Grounded conversation thread
│   │   └── EvidenceCitation.tsx     # Clickable reference to supporting event IDs
│   └── audit/
│       ├── AuditLedgerTable.tsx     # Paginated ledger entries
│       └── CryptographicVerifier.tsx# One-click sequential SHA-256 chain verification view
├── features/
│   ├── auth/                        # Login page, token persistence, role state
│   ├── dashboard/                   # SOC Executive Overview & SLA summary
│   ├── incidents/                   # Incident workbench, filtering, triage
│   ├── ingestion/                   # CSV/JSON upload, manual event form, demo controls
│   ├── simulation/                  # Digital twin response simulation workspace
│   ├── audit/                       # Ledger viewer and hash chain verification
│   └── governance/                  # Model metrics, retraining triggers, deployment gates
├── hooks/
│   ├── useAuth.ts                   # Role check, login/logout, token refresh
│   ├── useIncidents.ts              # TanStack query wrapper for incident queries
│   ├── useTimelineReplay.ts         # Step-by-step playback engine
│   └── useAuditVerification.ts      # Real-time SHA-256 chain integrity checker
├── services/
│   ├── api.ts                       # Axios client configured with JWT interceptors
│   ├── authService.ts
│   ├── incidentService.ts
│   ├── demoService.ts
│   ├── simulationService.ts
│   └── auditService.ts
└── types/
    ├── api.ts                       # Canonical API types & error definitions
    ├── events.ts                    # Event schema interfaces
    ├── incidents.ts                 # Incident, Risk, SLA, and MITRE types
    └── audit.ts                     # Audit record and verification interfaces
```

---

## 3. Application Routes & Navigation

| Route Path | View / Component | Minimum RBAC Role | Purpose |
| :--- | :--- | :--- | :--- |
| `/login` | `LoginPage` | Public | Analyst login & token issuance |
| `/` | `DashboardView` | Viewer | High-level SOC metrics, SLA health, severity breakdown |
| `/incidents` | `IncidentListView` | Viewer | Filterable grid of active and resolved incidents |
| `/incidents/:id` | `IncidentWorkbench` | Viewer (Masked) | Deep-dive triage, attack graph, timeline replay, copilot |
| `/simulation` | `SimulationView` | Incident Responder | Digital twin topology, proposed actions, blast-radius |
| `/ingestion` | `IngestionDemoView` | Security Analyst | CSV/JSON ingestion, deterministic synthetic demo scenarios |
| `/audit` | `AuditLedgerView` | Security Analyst | Hash-chained ledger view and verification engine |
| `/governance` | `ModelGovernanceView` | Security Admin | Precision/Recall/F1 metrics, model retrain & deploy |
| `/settings` | `SettingsView` | Security Admin | SLA thresholds, alert correlation window settings |

---

## 4. Custom React Flow Graph Architecture

The Attack Graph visualizes how an attacker moved laterally across entities.

### 4.1 Node Types
- `UserNode`: Renders username, user sensitivity badge (e.g., `Admin (100)`), and account state.
- `DeviceNode`: Renders workstation hostname, operating system, and isolation status.
- `ServerNode`: Renders server name, Tier level (Tier-1 DB, Tier-2 Web), and service status.
- `IpNode`: Renders IP address (masked for Viewers) and geolocation tag.
- `ProcessNode`: Renders binary name (e.g., `powershell.exe`), PID, and novelty indicator.
- `IncidentNode`: Focal cluster node displaying composite Risk Score and MITRE tactic tag.

### 4.2 Edge Types
- `logged_into`: Directed link from User to Device or Server.
- `connected_to`: Network connection between IP addresses or devices.
- `accessed`: File or credential access.
- `executed`: Process spawned by a user or parent process.
- `spawned`: Parent-child process relationship.
- `transferred_to`: Egress data transfer to external IP.
- `affected`: Edge connecting an incident to compromised entities.

---

## 5. Interactive Timeline Replay Engine

The incident replay engine allows analysts to walk through an attack step-by-step:

```typescript
// Replay State Machine Interface
interface ReplayState {
  isPlaying: boolean;
  playbackSpeed: 1 | 2 | 5; // Multiplier
  currentIndex: number;     // Active step in the sorted evidence sequence
  totalSteps: number;
  events: SecurityEvent[];
  activeHighlightedNodeIds: string[];
}
```

### Controls:
- **Play / Pause**: Initiates automated step advancement governed by `playbackSpeed`.
- **Step Forward / Backward**: Manual single-event scrubber enabling exact forensic examination.
- **Timeline Scrubber**: Drag-and-drop slider navigating across the event timestamps.
- **Dynamic Node Activation**: When a replay step fires, the corresponding React Flow nodes and edges pulse with an active highlight animation.

---

## 6. RBAC Privacy Redaction in the Frontend

To ensure non-privileged viewers cannot view sensitive PII, the frontend applies strict rendering guards:

```typescript
export function maskIpAddress(ip: string, userRole: string): string {
  if (userRole === 'Viewer') {
    // Mask host octets
    return ip.replace(/^(\d+\.\d+)\.\d+\.\d+$/, '$1.***.***');
  }
  return ip;
}

export function maskUsername(username: string, userRole: string): string {
  if (userRole === 'Viewer') {
    return username.charAt(0) + '***';
  }
  return username;
}
```

Action buttons (e.g., **Approve Simulated Response**, **Run Ingestion**, **Retrain Model**) check role authorization and display informative disabled tooltips if the current user lacks the required permission, while API route guards enforce authorization independently on the server.
