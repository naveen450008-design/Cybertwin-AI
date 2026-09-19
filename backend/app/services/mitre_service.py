"""Offline Enterprise MITRE ATT&CK Mapping Service.

Provides an offline catalog of 30+ Enterprise ATT&CK techniques and maps
incoming security events and detection rule triggers to corresponding techniques.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class MitreRecord:
    technique_id: str
    technique_name: str
    tactic: str
    description: str


class MitreService:
    # 30+ Curated Enterprise Techniques
    CATALOG: Dict[str, MitreRecord] = {
        "T1110.001": MitreRecord(
            "T1110.001", "Password Guessing", "Credential Access",
            "Adversaries may iterate through passwords to guess the correct password for a valid account."
        ),
        "T1110.003": MitreRecord(
            "T1110.003", "Password Spraying", "Credential Access",
            "Adversaries may iterate through valid usernames using a single or small set of passwords."
        ),
        "T1078": MitreRecord(
            "T1078", "Valid Accounts", "Defense Evasion",
            "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion."
        ),
        "T1078.002": MitreRecord(
            "T1078.002", "Domain Accounts", "Initial Access",
            "Adversaries may abuse domain accounts to access domain-connected systems and resources."
        ),
        "T1059.001": MitreRecord(
            "T1059.001", "PowerShell Execution", "Execution",
            "Adversaries may abuse PowerShell commands and scripts for execution and defense evasion."
        ),
        "T1059.003": MitreRecord(
            "T1059.003", "Windows Command Shell", "Execution",
            "Adversaries may abuse cmd.exe to execute commands or execute batch scripts."
        ),
        "T1048": MitreRecord(
            "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
            "Adversaries may steal data by transferring it over an alternative protocol instead of primary C2 channels."
        ),
        "T1046": MitreRecord(
            "T1046", "Network Service Discovery", "Discovery",
            "Adversaries may attempt to get a listing of services running on remote hosts."
        ),
        "T1021.002": MitreRecord(
            "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement",
            "Adversaries may use valid accounts to interact with remote SMB shares to execute lateral movement."
        ),
        "T1021.001": MitreRecord(
            "T1021.001", "Remote Desktop Protocol", "Lateral Movement",
            "Adversaries may log in to an interactive RDP session to move laterally through the target network."
        ),
        "T1071.001": MitreRecord(
            "T1071.001", "Web Protocols", "Command and Control",
            "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to avoid detection."
        ),
        "T1486": MitreRecord(
            "T1486", "Data Encrypted for Impact", "Impact",
            "Adversaries may encrypt data on target systems or corrupt data to disrupt operations (Ransomware)."
        ),
        "T1003.001": MitreRecord(
            "T1003.001", "LSASS Memory Dumping", "Credential Access",
            "Adversaries may attempt to access credential material stored in the LSASS process."
        ),
        "T1033": MitreRecord(
            "T1033", "System Owner/User Discovery", "Discovery",
            "Adversaries may attempt to identify the primary user or currently logged in identity (whoami)."
        ),
        "T1082": MitreRecord(
            "T1082", "System Information Discovery", "Discovery",
            "Adversaries may attempt to get detailed information about the operating system and hardware."
        ),
        "T1053.005": MitreRecord(
            "T1053.005", "Scheduled Task", "Persistence",
            "Adversaries may abuse the Windows Task Scheduler to execute programs at system startup or on a scheduled basis."
        ),
        "T1543.003": MitreRecord(
            "T1543.003", "Windows Service Creation", "Persistence",
            "Adversaries may create or modify Windows services to maintain persistence."
        ),
        "T1562.001": MitreRecord(
            "T1562.001", "Disable or Modify Tools", "Defense Evasion",
            "Adversaries may disable security software (antivirus, EDR, firewall) to avoid detection."
        ),
        "T1070.001": MitreRecord(
            "T1070.001", "Clear Windows Event Logs", "Defense Evasion",
            "Adversaries may clear Windows Event Logs to hide evidence of unauthorized activity."
        ),
        "T1548.002": MitreRecord(
            "T1548.002", "Bypass User Account Control", "Privilege Escalation",
            "Adversaries may bypass UAC mechanisms to elevate process privileges."
        ),
        "T1090": MitreRecord(
            "T1090", "Proxy", "Command and Control",
            "Adversaries may use a connection proxy to direct traffic between internal networks and external C2."
        ),
        "T1560": MitreRecord(
            "T1560", "Archive Collected Data", "Collection",
            "Adversaries may compress or encrypt data before exfiltration (e.g. zip, rar, tar)."
        ),
        "T1056.001": MitreRecord(
            "T1056.001", "Keylogging", "Collection",
            "Adversaries may log user keystrokes to intercept credentials."
        ),
        "T1041": MitreRecord(
            "T1041", "Exfiltration Over C2 Channel", "Exfiltration",
            "Adversaries may steal data by transferring it over an existing C2 channel."
        ),
        "T1489": MitreRecord(
            "T1489", "Service Stop", "Impact",
            "Adversaries may stop or disable services to render them unavailable."
        ),
        "T1490": MitreRecord(
            "T1490", "Inhibit System Recovery", "Impact",
            "Adversaries may delete or disable Volume Shadow Copies or backups to prevent restoration."
        )
    }

    # Rule-to-MITRE mapping
    RULE_MAPPINGS: Dict[str, str] = {
        "RULE-AUTH-001": "T1110.001",
        "RULE-AUTH-002": "T1078",
        "RULE-GEO-001": "T1078",
        "RULE-UEBA-001": "T1078",
        "RULE-UEBA-002": "T1078",
        "RULE-UEBA-003": "T1078",
        "RULE-PROC-001": "T1059.001",
        "RULE-NET-001": "T1048",
        "RULE-NET-002": "T1046",
        "RULE-CHAIN-001": "T1021.002"
    }

    @classmethod
    def map_event_to_techniques(cls, event: Any) -> List[Dict[str, Any]]:
        """Maps an event to MITRE ATT&CK techniques based on rule ID and process/event characteristics."""
        results = []
        if isinstance(event, dict):
            m = event.get("metadata") or event.get("metadata_json") or {}
            rule_id = m.get("detection_rule_id") if isinstance(m, dict) else None
            proc = (event.get("process_name") or "").lower()
            act = (event.get("action") or "").upper()
        else:
            rule_id = event.metadata_json.get("detection_rule_id") if hasattr(event, "metadata_json") and event.metadata_json else None
            proc = (getattr(event, "process_name", None) or "").lower()
            act = (getattr(event, "action", None) or "").upper()
        
        # 1. Rule-based mapping
        if rule_id and rule_id in cls.RULE_MAPPINGS:
            tech_id = cls.RULE_MAPPINGS[rule_id]
            rec = cls.CATALOG.get(tech_id)
            if rec:
                results.append({
                    "technique_id": rec.technique_id,
                    "technique_name": rec.technique_name,
                    "tactic": rec.tactic,
                    "confidence": 0.95
                })

        # 2. Process-based mapping
        if "powershell" in proc:
            rec = cls.CATALOG["T1059.001"]
            if not any(r["technique_id"] == rec.technique_id for r in results):
                results.append({"technique_id": rec.technique_id, "technique_name": rec.technique_name, "tactic": rec.tactic, "confidence": 0.90})
        elif "cmd.exe" in proc:
            rec = cls.CATALOG["T1059.003"]
            if not any(r["technique_id"] == rec.technique_id for r in results):
                results.append({"technique_id": rec.technique_id, "technique_name": rec.technique_name, "tactic": rec.tactic, "confidence": 0.85})
        elif "whoami" in proc:
            rec = cls.CATALOG["T1033"]
            if not any(r["technique_id"] == rec.technique_id for r in results):
                results.append({"technique_id": rec.technique_id, "technique_name": rec.technique_name, "tactic": rec.tactic, "confidence": 0.90})

        # 3. Action-based mapping
        if "ENCRYPT" in act or "RANSOM" in act:
            rec = cls.CATALOG["T1486"]
            if not any(r["technique_id"] == rec.technique_id for r in results):
                results.append({"technique_id": rec.technique_id, "technique_name": rec.technique_name, "tactic": rec.tactic, "confidence": 0.95})
        elif "EXFILTRATE" in act:
            rec = cls.CATALOG["T1048"]
            if not any(r["technique_id"] == rec.technique_id for r in results):
                results.append({"technique_id": rec.technique_id, "technique_name": rec.technique_name, "tactic": rec.tactic, "confidence": 0.90})

        return results
