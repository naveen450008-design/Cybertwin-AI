# Security Architecture, RBAC Matrix, Privacy Policy, and Audit Ledger

> **Classification**: Cryptographic Tamper-Evident Security & Enterprise Governance Specification  
> **Hash Standard**: SHA-256 (FIPS 180-4)  
> **Authentication**: JWT (RS256/HS256) with Passlib Bcrypt Password Hashing  
> **Privacy Standard**: Zero-Cleartext Credential Policy & RBAC Data Masking

---

## 1. Role-Based Access Control (RBAC) Matrix

The system enforces a strict 4-tier Role-Based Access Control hierarchy. Authorization is verified across three independent defense-in-depth boundaries:
1. **FastAPI Route Dependencies**: HTTP endpoint guards (`Depends(require_role(...))`).
2. **Service Layer Invariants**: Pre-execution capability validation inside domain service functions.
3. **Database Query Filtering**: Row-level redaction and column masking applied prior to serialization.

| System Capability | Viewer | Incident Responder | Security Analyst | Security Admin |
| :--- | :---: | :---: | :---: | :---: |
| **View Masked Dashboard & Telemetry** | Yes | Yes | Yes | Yes |
| **View Full Cleartext Incident Details** | No | Yes | Yes | Yes |
| **Ingest Raw Security Events (CSV / JSON / API)** | No | No | Yes | Yes |
| **Trigger Synthetic Demo Generators** | No | No | Yes | Yes |
| **Interact with AI Investigation Copilot** | Yes | Yes | Yes | Yes |
| **Approve Low-Impact Reversible Simulations** | No | Yes | Yes | Yes |
| **Approve High-Impact Simulations** (Isolate Device, Block IP) | No | No | Yes | Yes |
| **Review & Export Cryptographic Audit Logs** | No | No | Yes | Yes |
| **Trigger Baseline Retrain & Deploy ML Models** | No | No | No | Yes |
| **Manage User Accounts, Roles, & Global Settings** | No | No | No | Yes |

---

## 2. Privacy Policy & PII Masking Engine

### 2.1 RBAC Field Masking Rules
When an identity with the `Viewer` role queries endpoints returning events, incidents, or network traces, the serialization pipeline applies deterministic privacy redaction:
- **IPv4 Addresses**: Host identifier octets are replaced with asterisks (e.g., `192.168.1.104` $\to$ `192.168.***.***`).
- **IPv6 Addresses**: Interface identifier quads are masked (e.g., `2001:db8:85a3::8a2e:370:7334` $\to$ `2001:db8:85a3::****`).
- **Usernames & Identities**: Truncated with privacy asterisks (e.g., `alex.chen` $\to$ `a***` or `alex.c***@corp`).
- **Device Identifiers**: Retain prefix classification only (e.g., `DEV-WKS-012` $\to$ `DEV-WKS-***`).

### 2.2 Strict Zero-Cleartext Credential Policy
The platform enforces a non-negotiable architectural blacklist preventing sensitive credentials from ever entering persistence, logs, or UI outputs:

```python
FORBIDDEN_CREDENTIAL_KEYS = {
    "password",
    "auth_token",
    "access_token",
    "refresh_token",
    "private_key",
    "secret_key",
    "api_key",
    "session_cookie"
}
```

During ingestion, the normalizer strips any matching keys found in raw payloads. Under no circumstances are passwords or authorization secrets persisted or returned in API responses.

---

## 3. Tamper-Evident Hash-Chained Audit Ledger

Every critical state mutation—including incident updates, simulated containment approvals, ingestion batches, and model deployments—is committed to an append-only, cryptographically chained audit log.

### 3.1 Data Schema
Each audit record contains:
- `ledger_index`: Monotonically increasing 64-bit integer (`BIGSERIAL`).
- `audit_id`: UUIDv4 unique transaction identifier.
- `timestamp`: UTC ISO-8601 millisecond timestamp.
- `actor_username`: Authenticated user performing the mutation.
- `actor_role`: Verified RBAC role of the actor at execution time.
- `action_taken`: Explicit action code (e.g., `APPROVE_SIMULATED_ACTION`, `DEPLOY_MODEL_VERSION`).
- `target_entity_type`: Category of target (`INCIDENT`, `DEVICE`, `USER`, `MODEL`).
- `target_entity_id`: Primary identifier of the affected entity.
- `old_state_json`: Canonical JSON snapshot prior to mutation.
- `new_state_json`: Canonical JSON snapshot after mutation.
- `session_metadata`: Client IP, user-agent, and transaction correlation ID.
- `previous_hash`: SHA-256 digest of the immediately preceding audit record.
- `current_hash`: Cryptographically computed SHA-256 digest sealing this record.

### 3.2 Canonical Cryptographic Hash Formula
To guarantee byte-level determinism, JSON structures are serialized using canonical formatting (RFC 8785: sorted keys, zero whitespace between separators):

$$\text{CanonicalPayload}_n = \text{SerializeCanonical}(\{ \text{old\_state}, \text{new\_state}, \text{session\_metadata} \})$$

$$\text{CurrentHash}_n = \text{SHA256}(\text{PreviousHash}_{n-1} \parallel \text{Timestamp}_n \parallel \text{Actor}_n \parallel \text{Action}_n \parallel \text{CanonicalPayload}_n)$$

### 3.3 Genesis Record Definition
The initial anchor record (index `0` or initial seeded row) utilizes a standardized Genesis hash:
```text
Genesis Hash: 0000000000000000000000000000000000000000000000000000000000000000
```

---

## 4. Concurrency Control & Fork Prevention

To prevent audit chain branching caused by concurrent asynchronous write requests, the Audit Service enforces strict sequential database transactions:

```python
async with db.begin() as transaction:
    # 1. Acquire an exclusive row-level lock on the latest audit chain head
    result = await db.execute(
        select(AuditLedger)
        .order_by(AuditLedger.ledger_index.desc())
        .limit(1)
        .with_for_update() # Postgres SELECT FOR UPDATE guarantees serial execution
    )
    latest_record = result.scalar_one_or_none()
    
    previous_hash = latest_record.current_hash if latest_record else GENESIS_HASH
    new_index = (latest_record.ledger_index + 1) if latest_record else 1
    
    # 2. Compute the cryptographic hash for the new record
    current_hash = compute_sha256(
        previous_hash, timestamp, actor_username, action_taken, canonical_payload
    )
    
    # 3. Insert the new sealed record
    new_record = AuditLedger(
        ledger_index=new_index,
        previous_hash=previous_hash,
        current_hash=current_hash,
        # ... remaining fields ...
    )
    db.add(new_record)
    # Transaction commits, releasing lock for next concurrent write
```

This guarantees that two parallel requests cannot read the same `previous_hash`, ensuring an unbroken linear ledger.

---

## 5. Ledger Integrity Verification Algorithm

The verification endpoint (`GET /api/v1/audit/verify`) traverses the chain sequentially from genesis to head:

```python
async def verify_audit_chain(db: AsyncSession) -> VerificationReport:
    records = await db.execute(select(AuditLedger).order_by(AuditLedger.ledger_index.asc()))
    records = records.scalars().all()
    
    expected_previous_hash = GENESIS_HASH
    corrupted_entries = []
    
    for record in records:
        # Check 1: Chain continuity link
        if record.previous_hash != expected_previous_hash:
            corrupted_entries.append({
                "ledger_index": record.ledger_index,
                "error": "BROKEN_CHAIN_LINK",
                "expected_previous": expected_previous_hash,
                "actual_previous": record.previous_hash
            })
            
        # Check 2: Content integrity recomputation
        recomputed_hash = compute_sha256(
            record.previous_hash,
            record.timestamp,
            record.actor_username,
            record.action_taken,
            canonicalize(record.old_state_json, record.new_state_json, record.session_metadata)
        )
        
        if recomputed_hash != record.current_hash:
            corrupted_entries.append({
                "ledger_index": record.ledger_index,
                "error": "PAYLOAD_TAMPERING",
                "expected_hash": recomputed_hash,
                "stored_hash": record.current_hash
            })
            
        expected_previous_hash = record.current_hash
        
    return VerificationReport(
        is_valid=len(corrupted_entries) == 0,
        total_records_verified=len(records),
        corrupted_records=corrupted_entries
    )
```

---

## 6. API Transport & Session Security

- **JWT Signing**: Access tokens signed using HMAC-SHA256 with a 32-byte cryptographically random secret key, valid for 60 minutes. Refresh tokens valid for 7 days.
- **Password Storage**: Passwords hashed with `bcrypt` (work factor 12) via `passlib`.
- **CORS Policy**: Whitelist restricted to configured frontend domains (e.g., `http://localhost:5173` in development).
- **Rate Limiting**: Critical endpoints (e.g., `/api/v1/auth/login`, `/api/v1/events/ingest`) throttled via token-bucket rate limiting (e.g., 5 login attempts/minute per IP).
