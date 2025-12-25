"""Synthetic Security Alert Data Generator.
========================================

Generates realistic security alerts with expert triage decisions
for training machine learning models.

This module provides:
- SecurityAlertGenerator: Main class for generating alerts
- AlertCategory: Enum of 12 security alert categories
- Severity: Alert severity levels
- TriageDecision: Possible triage outcomes

Example:
    >>> from soc_triage_agent import SecurityAlertGenerator
    >>> generator = SecurityAlertGenerator(seed=42)
    >>> alert, triage = generator.generate_alert()
    >>> print(f"Category: {alert.category}, Decision: {triage.decision}")

"""

import json
import random
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Severity(Enum):
    """Security alert severity levels following common SIEM conventions."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def priority_weight(self) -> int:
        """Return numeric priority weight (lower = more urgent)."""
        weights = {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFORMATIONAL: 5,
        }
        return weights[self]


class TriageDecision(Enum):
    """Possible triage decisions for security alerts."""

    ESCALATE = "escalate"  # Immediate escalation to incident response
    INVESTIGATE = "investigate"  # Requires analyst investigation
    MONITOR = "monitor"  # Continue monitoring, no immediate action
    FALSE_POSITIVE = "false_positive"  # Benign activity incorrectly flagged
    CLOSE = "close"  # No action needed, close alert

    @property
    def requires_action(self) -> bool:
        """Whether this decision requires immediate analyst action."""
        return self in [TriageDecision.ESCALATE, TriageDecision.INVESTIGATE]


class AlertCategory(Enum):
    """Categories of security alerts based on MITRE ATT&CK framework."""

    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    INSIDER_THREAT = "insider_threat"
    POLICY_VIOLATION = "policy_violation"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"
    RECONNAISSANCE = "reconnaissance"
    DENIAL_OF_SERVICE = "denial_of_service"

    @property
    def mitre_tactics(self) -> list[str]:
        """Return associated MITRE ATT&CK tactics."""
        mapping = {
            AlertCategory.MALWARE: [
                "TA0002",
                "TA0003",
                "TA0005",
            ],  # Execution, Persistence, Defense Evasion
            AlertCategory.PHISHING: ["TA0001", "TA0043"],  # Initial Access, Reconnaissance
            AlertCategory.BRUTE_FORCE: ["TA0006"],  # Credential Access
            AlertCategory.DATA_EXFILTRATION: ["TA0010", "TA0009"],  # Exfiltration, Collection
            AlertCategory.PRIVILEGE_ESCALATION: ["TA0004"],  # Privilege Escalation
            AlertCategory.LATERAL_MOVEMENT: ["TA0008"],  # Lateral Movement
            AlertCategory.COMMAND_AND_CONTROL: ["TA0011"],  # Command and Control
            AlertCategory.INSIDER_THREAT: ["TA0009", "TA0010"],  # Collection, Exfiltration
            AlertCategory.POLICY_VIOLATION: [],  # Not directly mapped
            AlertCategory.VULNERABILITY_EXPLOIT: ["TA0001", "TA0002"],  # Initial Access, Execution
            AlertCategory.RECONNAISSANCE: ["TA0043"],  # Reconnaissance
            AlertCategory.DENIAL_OF_SERVICE: ["TA0040"],  # Impact
        }
        return mapping.get(self, [])


@dataclass
class UserContext:
    """Context information about the user involved in the alert."""

    username: str
    email: str
    department: str
    role: str
    location: str
    risk_level: str  # low, medium, high
    is_vip: bool
    employment_status: str  # active, notice_period, terminated, contractor
    account_age_days: int
    last_training_days: int  # Days since security awareness training
    previous_incidents: int


@dataclass
class AssetContext:
    """Context information about the affected asset."""

    hostname: str
    asset_id: str
    asset_type: str  # workstation, server, laptop, etc.
    operating_system: str
    criticality: str  # critical, high, medium, low
    data_classification: str  # public, internal, confidential, restricted
    patch_status: str  # current, behind, critical_missing
    last_scan_days: int
    owner: str
    business_unit: str


@dataclass
class NetworkContext:
    """Network context for the alert."""

    source_ip: str
    destination_ip: Optional[str]
    source_zone: str  # internal, dmz, external, guest, vpn
    destination_zone: Optional[str]
    protocol: str
    port: Optional[int]
    bytes_transferred: Optional[int]
    geo_location: Optional[str]
    is_encrypted: bool


@dataclass
class EnvironmentContext:
    """Environmental context at the time of the alert."""

    is_business_hours: bool
    is_change_window: bool
    is_holiday: bool
    active_incidents: int
    threat_level: str  # normal, elevated, high, critical
    recent_deployments: list[str]


@dataclass
class SecurityAlert:
    """A complete security alert with all context."""

    alert_id: str
    timestamp: str
    source_system: str
    category: str
    severity: str
    title: str
    description: str
    affected_assets: list[str]
    indicators: dict[str, Any]
    user_context: dict[str, Any]
    asset_context: dict[str, Any]
    network_context: dict[str, Any]
    environment_context: dict[str, Any]
    raw_log: str
    mitre_techniques: list[str] = field(default_factory=list)
    related_alerts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class TriageResponse:
    """Triage recommendation for a security alert."""

    decision: str
    priority: int  # 1-5, where 1 is highest
    confidence_score: float  # 0.0 - 1.0
    reasoning: str
    key_factors: list[str]
    recommended_actions: list[str]
    escalation_required: bool
    escalation_target: Optional[str]
    estimated_impact: str  # none, low, moderate, high, severe
    estimated_urgency: str  # immediate, hours, day, week
    additional_investigation: list[str]
    ioc_extraction: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class AlertTemplates:
    """Templates for generating realistic security alerts."""

    MALWARE_TEMPLATES = {
        "titles": [
            "Suspicious executable detected on endpoint",
            "Known malware signature identified: {malware_family}",
            "Ransomware behavior detected - file encryption activity",
            "Trojan activity observed - suspicious network connections",
            "Cryptominer process detected consuming resources",
            "Fileless malware execution via PowerShell",
            "Malicious macro execution in Office document",
            "Suspicious DLL side-loading detected",
            "Memory-resident malware identified",
            "Rootkit indicators detected on system",
        ],
        "sources": [
            "CrowdStrike Falcon",
            "Microsoft Defender for Endpoint",
            "Carbon Black",
            "SentinelOne",
            "Symantec Endpoint Protection",
            "Cisco Secure Endpoint",
            "Trend Micro Apex One",
            "Sophos Intercept X",
        ],
        "malware_families": [
            "Emotet",
            "TrickBot",
            "QakBot",
            "Cobalt Strike",
            "Ryuk",
            "Conti",
            "LockBit",
            "BlackCat",
            "REvil",
            "Dridex",
        ],
    }

    PHISHING_TEMPLATES = {
        "titles": [
            "Phishing email detected - credential harvesting attempt",
            "Business email compromise attempt from {sender_domain}",
            "Spear phishing campaign targeting {department}",
            "Malicious attachment quarantined - {file_type} file",
            "OAuth consent phishing detected",
            "QR code phishing attempt (quishing)",
            "Voice phishing (vishing) attempt reported",
            "Callback phishing - fake invoice notification",
            "Brand impersonation detected - {brand} lookalike",
            "Compromised vendor email used for phishing",
        ],
        "sources": [
            "Proofpoint",
            "Microsoft Defender for Office 365",
            "Mimecast",
            "Abnormal Security",
            "Barracuda Email Security",
            "Cisco Secure Email",
        ],
        "subject_lines": [
            "Urgent: Password Reset Required",
            "Invoice #{invoice_num} - Payment Overdue",
            "Your account has been compromised",
            "Action Required: Verify your identity",
            "Shared document from {name}",
            "IT Support: System Maintenance Notice",
            "HR: Updated Benefits Information",
            "Bonus Payment Confirmation",
            "Voicemail from {phone}",
            "Meeting Recording Available",
        ],
    }

    BRUTE_FORCE_TEMPLATES = {
        "titles": [
            "Multiple failed login attempts detected - {count} failures",
            "Password spray attack in progress from {source_count} IPs",
            "Credential stuffing attack detected",
            "SSH brute force attempt from {source_ip}",
            "RDP brute force attack - account lockout triggered",
            "API authentication brute force detected",
            "LDAP enumeration and password guessing",
            "Kerberos pre-authentication failures spike",
            "MFA fatigue attack detected - repeated push notifications",
            "VPN authentication brute force attempt",
        ],
        "sources": [
            "Azure AD Identity Protection",
            "Okta",
            "CrowdStrike Falcon Identity",
            "Duo Security",
            "SailPoint",
            "Ping Identity",
            "Microsoft Sentinel",
        ],
    }

    DATA_EXFILTRATION_TEMPLATES = {
        "titles": [
            "Unusual data transfer volume: {volume}GB to external IP",
            "Sensitive file upload to personal cloud storage",
            "Data transfer to high-risk country: {country}",
            "USB mass storage - large data copy detected",
            "Email with large attachment to external recipient",
            "Database export to unauthorized location",
            "Screen capture tool accessing sensitive data",
            "Clipboard data containing sensitive information",
            "Print job with classified document",
            "Compressed archive created with sensitive files",
        ],
        "sources": [
            "Microsoft Defender for Cloud Apps",
            "Netskope",
            "Zscaler",
            "Varonis",
            "Digital Guardian",
            "Forcepoint DLP",
            "Symantec DLP",
        ],
        "high_risk_countries": ["CN", "RU", "KP", "IR", "BY", "SY"],
    }

    PRIVILEGE_ESCALATION_TEMPLATES = {
        "titles": [
            "Local privilege escalation attempt via {technique}",
            "Unauthorized admin group membership change",
            "Suspicious token manipulation detected",
            "UAC bypass attempt using {method}",
            "Service account privilege abuse",
            "Kerberoasting attack detected",
            "AS-REP roasting attempt",
            "Golden ticket usage suspected",
            "DCSync attack detected",
            "Sudo privilege escalation attempt",
        ],
        "sources": [
            "CrowdStrike Falcon",
            "Microsoft Defender for Identity",
            "Tenable.ad",
            "Varonis",
            "SentinelOne",
            "Elastic Security",
        ],
        "techniques": [
            "DLL hijacking",
            "unquoted service path",
            "token impersonation",
            "kernel exploit",
            "misconfigured SUID",
            "capability abuse",
        ],
    }

    LATERAL_MOVEMENT_TEMPLATES = {
        "titles": [
            "Pass-the-hash attack detected from {source}",
            "WMI lateral movement to {target_count} systems",
            "PsExec execution from unusual source",
            "RDP connection chain detected",
            "SMB lateral movement with stolen credentials",
            "WinRM lateral movement detected",
            "SSH pivoting through compromised host",
            "DCOM lateral movement observed",
            "Remote service creation on {target}",
            "Admin share access from non-admin workstation",
        ],
        "sources": [
            "Microsoft Defender for Identity",
            "CrowdStrike Falcon",
            "Vectra AI",
            "ExtraHop",
            "Darktrace",
            "Microsoft Sentinel",
        ],
    }

    C2_TEMPLATES = {
        "titles": [
            "Beaconing activity detected - {interval}s interval",
            "Known C2 domain contacted: {domain}",
            "DNS tunneling detected to {domain}",
            "Encrypted C2 traffic pattern identified",
            "Cobalt Strike beacon signatures detected",
            "Reverse shell connection established",
            "Domain fronting C2 communication",
            "Fast-flux DNS activity observed",
            "Custom protocol C2 detected on port {port}",
            "Tor traffic from endpoint",
        ],
        "sources": [
            "Palo Alto Networks",
            "Cisco Umbrella",
            "Zscaler",
            "CrowdStrike Falcon",
            "Darktrace",
            "Vectra AI",
            "ExtraHop",
        ],
        "c2_frameworks": [
            "Cobalt Strike",
            "Metasploit",
            "Empire",
            "Covenant",
            "Sliver",
            "Brute Ratel",
            "Havoc",
            "Mythic",
        ],
    }

    INSIDER_THREAT_TEMPLATES = {
        "titles": [
            "Unusual after-hours access by {user}",
            "Mass file download by employee on notice period",
            "Access to unauthorized resources - {resource}",
            "Anomalous user behavior score: {score}/100",
            "Privilege abuse by administrator",
            "Sensitive data access pattern change",
            "Unauthorized use of service account",
            "Data hoarding behavior detected",
            "Circumvention of security controls",
            "Competitor contact by employee with data access",
        ],
        "sources": [
            "Microsoft Insider Risk Management",
            "Securonix",
            "Exabeam",
            "Varonis",
            "ObserveIT",
            "DTEX",
            "Code42 Incydr",
        ],
    }

    POLICY_VIOLATION_TEMPLATES = {
        "titles": [
            "Unauthorized software installation: {software}",
            "VPN split tunneling violation",
            "Shadow IT application detected: {app}",
            "Data residency violation - {region}",
            "Encryption policy violation on {asset}",
            "Removable media policy violation",
            "Password policy violation",
            "Remote access policy breach",
            "BYOD compliance failure",
            "Third-party access policy violation",
        ],
        "sources": [
            "Microsoft Intune",
            "Tanium",
            "Qualys",
            "ServiceNow",
            "BigFix",
            "Jamf",
            "VMware Workspace ONE",
        ],
        "frameworks": ["SOC2", "HIPAA", "PCI-DSS", "GDPR", "ISO27001", "NIST", "FedRAMP"],
    }

    VULNERABILITY_TEMPLATES = {
        "titles": [
            "Critical vulnerability exploited: {cve}",
            "Zero-day exploit attempt detected",
            "Web application attack: {attack_type}",
            "SQL injection attempt blocked",
            "Remote code execution attempt on {service}",
            "Path traversal attack detected",
            "XXE injection attempt",
            "SSRF attack targeting internal resources",
            "Deserialization vulnerability exploit",
            "Log4Shell exploitation attempt",
        ],
        "sources": [
            "Tenable",
            "Qualys",
            "Rapid7",
            "Microsoft Defender",
            "AWS GuardDuty",
            "Palo Alto Cortex XDR",
            "Snyk",
        ],
        "attack_types": [
            "SQL Injection",
            "XSS",
            "CSRF",
            "Command Injection",
            "LDAP Injection",
            "XML Injection",
            "Buffer Overflow",
        ],
    }

    RECONNAISSANCE_TEMPLATES = {
        "titles": [
            "Port scanning detected from {source}",
            "Network enumeration attempt - {ports} ports scanned",
            "LDAP enumeration of Active Directory",
            "DNS zone transfer attempt",
            "Web application fingerprinting",
            "SNMP enumeration detected",
            "SMB share enumeration",
            "User enumeration via {method}",
            "Service version probing",
            "Cloud resource enumeration",
        ],
        "sources": [
            "Palo Alto Networks",
            "Cisco Firepower",
            "Suricata",
            "Zeek",
            "AWS GuardDuty",
            "Azure Sentinel",
            "Darktrace",
        ],
    }

    DOS_TEMPLATES = {
        "titles": [
            "DDoS attack detected - {volume} Gbps",
            "Application layer attack on {service}",
            "SYN flood attack in progress",
            "DNS amplification attack",
            "HTTP flood attack detected",
            "Slowloris attack targeting web servers",
            "NTP amplification attack",
            "Resource exhaustion attack",
            "BGP hijacking attempt",
            "Ransom DDoS (RDoS) threat received",
        ],
        "sources": [
            "Cloudflare",
            "Akamai",
            "AWS Shield",
            "Azure DDoS Protection",
            "Arbor Networks",
            "Radware",
            "Imperva",
        ],
    }


class SecurityAlertGenerator:
    """Generates synthetic security alerts with expert triage decisions.

    This generator creates realistic security alerts across 12 categories,
    complete with contextual information and appropriate triage responses.

    Attributes:
        seed: Random seed for reproducibility

    Example:
        >>> generator = SecurityAlertGenerator(seed=42)
        >>> alert, triage = generator.generate_alert()
        >>> dataset = generator.generate_dataset(1000, format="huggingface")

    """

    def __init__(self, seed: Optional[int] = None):
        """Initialize the generator.

        Args:
            seed: Random seed for reproducibility

        """
        self.seed = seed
        # Use a per-instance Random object for reproducibility
        self._rng = random.Random(seed)
        self.templates = AlertTemplates()
        self._alert_counter = 0

    def _generate_ip(self, internal: bool = False) -> str:
        """Generate a random IP address."""
        if internal:
            prefixes = ["10.", "172.16.", "192.168."]
            prefix = self._rng.choice(prefixes)
            if prefix == "10.":
                return f"10.{self._rng.randint(0,255)}.{self._rng.randint(0,255)}.{self._rng.randint(1,254)}"
            elif prefix == "172.16.":
                return f"172.{self._rng.randint(16,31)}.{self._rng.randint(0,255)}.{self._rng.randint(1,254)}"
            else:
                return f"192.168.{self._rng.randint(0,255)}.{self._rng.randint(1,254)}"
        else:
            return f"{self._rng.randint(1,223)}.{self._rng.randint(0,255)}.{self._rng.randint(0,255)}.{self._rng.randint(1,254)}"

    def _generate_hash(self, hash_type: str = "sha256") -> str:
        """Generate a random hash."""
        lengths = {"md5": 32, "sha1": 40, "sha256": 64}
        length = lengths.get(hash_type, 64)
        return "".join(self._rng.choices("0123456789abcdef", k=length))

    def _generate_domain(self, suspicious: bool = False) -> str:
        """Generate a random domain name."""
        if suspicious:
            tlds = [".xyz", ".top", ".club", ".info", ".tk", ".ml"]
            name_len = self._rng.randint(8, 16)
        else:
            tlds = [".com", ".net", ".org", ".io", ".co"]
            name_len = self._rng.randint(5, 12)

        name = "".join(self._rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=name_len))
        return name + self._rng.choice(tlds)

    def _generate_user_context(self) -> UserContext:
        """Generate user context information."""
        first_names = [
            "john",
            "jane",
            "michael",
            "sarah",
            "david",
            "emma",
            "james",
            "olivia",
            "robert",
            "sophia",
        ]
        last_names = [
            "smith",
            "johnson",
            "williams",
            "brown",
            "jones",
            "garcia",
            "miller",
            "davis",
            "martinez",
            "wilson",
        ]
        departments = [
            "Engineering",
            "Finance",
            "HR",
            "Sales",
            "IT",
            "Legal",
            "Marketing",
            "Operations",
            "Executive",
            "Research",
        ]
        roles = [
            "Analyst",
            "Manager",
            "Director",
            "VP",
            "Developer",
            "Administrator",
            "Specialist",
            "Coordinator",
            "Intern",
            "Consultant",
        ]
        locations = [
            "New York",
            "San Francisco",
            "London",
            "Tokyo",
            "Singapore",
            "Austin",
            "Seattle",
            "Chicago",
            "Remote",
            "Berlin",
        ]

        first = self._rng.choice(first_names)
        last = self._rng.choice(last_names)

        return UserContext(
            username=f"{first}.{last}",
            email=f"{first}.{last}@company.com",
            department=self._rng.choice(departments),
            role=self._rng.choice(roles),
            location=self._rng.choice(locations),
            risk_level=self._rng.choices(["low", "medium", "high"], weights=[0.6, 0.3, 0.1])[0],
            is_vip=self._rng.random() < 0.1,
            employment_status=self._rng.choices(
                ["active", "notice_period", "terminated", "contractor"],
                weights=[0.85, 0.05, 0.02, 0.08],
            )[0],
            account_age_days=self._rng.randint(30, 3650),
            last_training_days=self._rng.randint(0, 365),
            previous_incidents=self._rng.choices([0, 1, 2, 3], weights=[0.7, 0.2, 0.07, 0.03])[0],
        )

    def _generate_asset_context(self) -> AssetContext:
        """Generate asset context information."""
        asset_types = [
            "workstation",
            "server",
            "laptop",
            "domain_controller",
            "database",
            "web_server",
            "file_server",
            "mail_server",
        ]
        os_options = [
            "Windows 11",
            "Windows 10",
            "Windows Server 2022",
            "Windows Server 2019",
            "Ubuntu 22.04",
            "RHEL 8",
            "macOS Ventura",
            "CentOS 7",
        ]
        business_units = [
            "Corporate",
            "Engineering",
            "Finance",
            "HR",
            "IT",
            "Sales",
            "Marketing",
            "Research",
        ]

        asset_type = self._rng.choice(asset_types)
        prefix = {
            "workstation": "WS",
            "server": "SRV",
            "laptop": "LAP",
            "domain_controller": "DC",
            "database": "DB",
        }.get(asset_type, "HOST")

        return AssetContext(
            hostname=f"{prefix}-{self._rng.randint(100, 999)}",
            asset_id=f"ASSET-{uuid.uuid4().hex[:8].upper()}",
            asset_type=asset_type,
            operating_system=self._rng.choice(os_options),
            criticality=self._rng.choices(
                ["critical", "high", "medium", "low"], weights=[0.1, 0.25, 0.45, 0.2]
            )[0],
            data_classification=self._rng.choices(
                ["public", "internal", "confidential", "restricted"], weights=[0.2, 0.4, 0.3, 0.1]
            )[0],
            patch_status=self._rng.choices(
                ["current", "behind", "critical_missing"], weights=[0.6, 0.3, 0.1]
            )[0],
            last_scan_days=self._rng.randint(0, 30),
            owner=f"{self._rng.choice(['john', 'jane', 'admin', 'system'])}.{self._rng.choice(['smith', 'doe', 'admin'])}",
            business_unit=self._rng.choice(business_units),
        )

    def _generate_network_context(self, external_threat: bool = False) -> NetworkContext:
        """Generate network context information."""
        protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SMB", "RDP", "SSH"]
        zones = ["internal", "dmz", "external", "guest", "vpn"]
        countries = ["US", "GB", "DE", "JP", "CN", "RU", "BR", "IN", "AU", "FR"]

        return NetworkContext(
            source_ip=self._generate_ip(internal=not external_threat),
            destination_ip=(
                self._generate_ip(internal=self._rng.random() > 0.5)
                if self._rng.random() > 0.3
                else None
            ),
            source_zone=(
                "external" if external_threat else self._rng.choice(["internal", "vpn", "guest"])
            ),
            destination_zone=self._rng.choice(zones) if self._rng.random() > 0.3 else None,
            protocol=self._rng.choice(protocols),
            port=self._rng.choice([22, 80, 443, 445, 3389, 8080, 8443, None]),
            bytes_transferred=(
                self._rng.randint(1000, 100000000) if self._rng.random() > 0.5 else None
            ),
            geo_location=self._rng.choice(countries) if self._rng.random() > 0.4 else None,
            is_encrypted=self._rng.random() > 0.3,
        )

    def _generate_environment_context(self) -> EnvironmentContext:
        """Generate environment context information."""
        return EnvironmentContext(
            is_business_hours=self._rng.random() > 0.3,
            is_change_window=self._rng.random() < 0.1,
            is_holiday=self._rng.random() < 0.05,
            active_incidents=self._rng.choices(
                [0, 1, 2, 3, 4, 5], weights=[0.5, 0.25, 0.12, 0.08, 0.03, 0.02]
            )[0],
            threat_level=self._rng.choices(
                ["normal", "elevated", "high", "critical"], weights=[0.7, 0.2, 0.08, 0.02]
            )[0],
            recent_deployments=self._rng.sample(
                ["web-app-v2.1", "database-patch", "security-update", "new-feature"],
                k=self._rng.randint(0, 2),
            ),
        )

    def _generate_raw_log(
        self, category: AlertCategory, indicators: dict[str, Any], timestamp: str
    ) -> str:
        """Generate a realistic raw log entry."""
        log_formats = {
            AlertCategory.MALWARE: "{ts} MALWARE: hash={hash} file={file} process={proc} action=quarantine severity=high",
            AlertCategory.PHISHING: '{ts} PHISH: from={sender} subject="{subject}" verdict=malicious action=block',
            AlertCategory.BRUTE_FORCE: "{ts} AUTH: event=failed_login attempts={attempts} source={source} target={target}",
            AlertCategory.DATA_EXFILTRATION: "{ts} DLP: action=block volume={volume}MB destination={dest} classification={class}",
            AlertCategory.PRIVILEGE_ESCALATION: "{ts} PRIVESC: technique={technique} from={from_priv} to={to_priv} success={success}",
            AlertCategory.LATERAL_MOVEMENT: "{ts} LATERAL: src={src} dst={dst} protocol={proto} method={method}",
            AlertCategory.COMMAND_AND_CONTROL: "{ts} C2: domain={domain} beacon_interval={interval}s protocol={proto} confidence=high",
            AlertCategory.INSIDER_THREAT: "{ts} INSIDER: user={user} risk_score={score} behavior={behavior} alert_type=anomaly",
            AlertCategory.POLICY_VIOLATION: "{ts} POLICY: violation={violation} policy={policy} user={user} asset={asset}",
            AlertCategory.VULNERABILITY_EXPLOIT: "{ts} EXPLOIT: cve={cve} cvss={cvss} target={target} success={success}",
            AlertCategory.RECONNAISSANCE: "{ts} RECON: type={type} source={source} ports_scanned={ports} duration={duration}min",
            AlertCategory.DENIAL_OF_SERVICE: "{ts} DDOS: type={type} volume={volume}Gbps sources={sources} target={target}",
        }

        template = log_formats.get(category, "{ts} ALERT: category={category} severity=high")

        # Build format kwargs from indicators
        format_kwargs = {"ts": timestamp, "category": category.value}
        format_kwargs.update({k: str(v)[:50] for k, v in indicators.items()})

        try:
            return template.format(**format_kwargs)
        except KeyError:
            return (
                f"{timestamp} ALERT: category={category.value} indicators={json.dumps(indicators)}"
            )

    def _generate_indicators(self, category: AlertCategory) -> dict[str, Any]:
        """Generate category-specific indicators of compromise."""
        if category == AlertCategory.MALWARE:
            return {
                "file_hash": self._generate_hash("sha256"),
                "file_name": self._rng.choice(
                    [
                        "svchost.exe",
                        "update.exe",
                        "installer.msi",
                        "document.pdf.exe",
                        "chrome_update.exe",
                        "winlogon.exe",
                    ]
                ),
                "file_path": self._rng.choice(
                    [
                        "C:\\Users\\Public\\",
                        "C:\\Windows\\Temp\\",
                        "C:\\ProgramData\\",
                        "/tmp/",
                        "/var/tmp/",
                    ]
                ),
                "process_id": self._rng.randint(1000, 65535),
                "parent_process": self._rng.choice(
                    ["explorer.exe", "cmd.exe", "powershell.exe", "outlook.exe", "winword.exe"]
                ),
                "detection_method": self._rng.choice(
                    ["signature", "behavioral", "heuristic", "machine_learning", "sandbox"]
                ),
                "malware_family": self._rng.choice(
                    AlertTemplates.MALWARE_TEMPLATES["malware_families"]
                ),
                "command_line": f"{self._rng.choice(['powershell', 'cmd', 'wscript'])} -enc {self._generate_hash('md5')[:32]}",
            }

        elif category == AlertCategory.PHISHING:
            return {
                "sender_email": f"{''.join(self._rng.choices('abcdefghijklmnopqrstuvwxyz', k=8))}@{self._generate_domain(suspicious=True)}",
                "sender_display_name": self._rng.choice(
                    ["IT Support", "HR Department", "CEO Office", "Microsoft Support", "Help Desk"]
                ),
                "subject_line": self._rng.choice(
                    AlertTemplates.PHISHING_TEMPLATES["subject_lines"]
                ).format(
                    invoice_num=self._rng.randint(10000, 99999),
                    name=self._rng.choice(["John", "HR Team", "Your Manager"]),
                    phone=f"+1-{self._rng.randint(200,999)}-{self._rng.randint(100,999)}-{self._rng.randint(1000,9999)}",
                ),
                "urls_count": self._rng.randint(1, 5),
                "malicious_urls": [
                    f"https://{self._generate_domain(suspicious=True)}/login"
                    for _ in range(self._rng.randint(1, 3))
                ],
                "attachment_count": self._rng.randint(0, 2),
                "attachment_types": self._rng.sample(
                    [".docx", ".xlsx", ".pdf", ".html", ".zip"], k=self._rng.randint(0, 2)
                ),
                "is_spoofed": self._rng.choice([True, False]),
                "spf_result": self._rng.choice(["pass", "fail", "softfail", "none"]),
                "dkim_result": self._rng.choice(["pass", "fail", "none"]),
            }

        elif category == AlertCategory.BRUTE_FORCE:
            return {
                "failed_attempts": self._rng.randint(10, 10000),
                "time_window_minutes": self._rng.randint(5, 120),
                "unique_passwords": self._rng.randint(5, 1000),
                "source_ips": [self._generate_ip() for _ in range(self._rng.randint(1, 50))],
                "source_ip_count": self._rng.randint(1, 50),
                "target_accounts": self._rng.randint(1, 500),
                "target_account_list": [
                    f"user{i}@company.com" for i in range(self._rng.randint(1, 5))
                ],
                "successful_auth": self._rng.choice(
                    [True, False, False, False]
                ),  # 25% success rate
                "lockouts_triggered": self._rng.randint(0, 20),
                "auth_protocol": self._rng.choice(["LDAP", "Kerberos", "NTLM", "OAuth", "SAML"]),
            }

        elif category == AlertCategory.DATA_EXFILTRATION:
            return {
                "volume_mb": self._rng.randint(100, 100000),
                "destination_ip": self._generate_ip(),
                "destination_domain": self._generate_domain(suspicious=self._rng.random() > 0.5),
                "destination_country": self._rng.choice(["US", "CN", "RU", "GB", "DE", "Unknown"]),
                "destination_service": self._rng.choice(
                    ["Dropbox", "Google Drive", "OneDrive", "WeTransfer", "Custom", "Unknown"]
                ),
                "file_types": self._rng.sample(
                    ["pdf", "xlsx", "docx", "zip", "sql", "csv", "pst", "rar"],
                    k=self._rng.randint(1, 4),
                ),
                "file_count": self._rng.randint(1, 1000),
                "data_classification": self._rng.choice(
                    ["public", "internal", "confidential", "restricted"]
                ),
                "transfer_method": self._rng.choice(
                    ["HTTP", "HTTPS", "FTP", "SFTP", "Email", "USB"]
                ),
                "encryption_detected": self._rng.choice([True, False]),
            }

        elif category == AlertCategory.PRIVILEGE_ESCALATION:
            return {
                "original_privilege": self._rng.choice(
                    ["user", "guest", "service_account", "standard"]
                ),
                "target_privilege": self._rng.choice(
                    ["local_admin", "domain_admin", "system", "root", "enterprise_admin"]
                ),
                "technique": self._rng.choice(
                    AlertTemplates.PRIVILEGE_ESCALATION_TEMPLATES["techniques"]
                ),
                "mitre_technique": self._rng.choice(
                    ["T1548", "T1134", "T1068", "T1078", "T1055", "T1574"]
                ),
                "success": self._rng.choice([True, False]),
                "tool_used": self._rng.choice(
                    ["Mimikatz", "Rubeus", "PowerUp", "WinPEAS", "Custom", "Unknown"]
                ),
                "target_account": f"admin_{self._rng.randint(1, 100)}",
            }

        elif category == AlertCategory.LATERAL_MOVEMENT:
            return {
                "source_host": f"WS-{self._rng.randint(100, 999)}",
                "destination_hosts": [
                    f"SRV-{self._rng.randint(10, 99)}" for _ in range(self._rng.randint(1, 10))
                ],
                "destination_count": self._rng.randint(1, 10),
                "protocol": self._rng.choice(["SMB", "WMI", "RDP", "WinRM", "SSH", "PSRemoting"]),
                "credentials_type": self._rng.choice(
                    [
                        "pass_the_hash",
                        "pass_the_ticket",
                        "valid_credentials",
                        "stolen_token",
                        "service_account",
                    ]
                ),
                "tool_used": self._rng.choice(
                    ["PsExec", "WMIExec", "Invoke-Command", "CrackMapExec", "Impacket", "Native"]
                ),
                "mitre_technique": self._rng.choice(
                    ["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.006"]
                ),
            }

        elif category == AlertCategory.COMMAND_AND_CONTROL:
            return {
                "destination_domain": self._generate_domain(suspicious=True),
                "destination_ip": self._generate_ip(),
                "beacon_interval_seconds": self._rng.choice(
                    [30, 60, 120, 300, 600, 900, 1800, 3600]
                ),
                "jitter_percentage": self._rng.randint(0, 50),
                "protocol": self._rng.choice(["HTTPS", "HTTP", "DNS", "ICMP", "Custom"]),
                "c2_framework": (
                    self._rng.choice(AlertTemplates.C2_TEMPLATES["c2_frameworks"])
                    if self._rng.random() > 0.5
                    else "Unknown"
                ),
                "threat_intel_match": self._rng.choice([True, False]),
                "data_encoded": self._rng.choice([True, False]),
                "bytes_sent": self._rng.randint(100, 10000),
                "bytes_received": self._rng.randint(100, 100000),
            }

        elif category == AlertCategory.INSIDER_THREAT:
            return {
                "user_risk_score": self._rng.randint(50, 100),
                "behavior_anomaly": self._rng.choice(
                    [
                        "access_time",
                        "data_volume",
                        "resource_access",
                        "geographic",
                        "device_change",
                        "pattern_deviation",
                    ]
                ),
                "employment_status": self._rng.choice(
                    ["active", "notice_period", "terminated", "contractor"]
                ),
                "historical_violations": self._rng.randint(0, 5),
                "data_accessed_classification": self._rng.choice(
                    ["internal", "confidential", "restricted"]
                ),
                "peer_group_deviation": self._rng.uniform(2.0, 5.0),
                "resources_accessed": self._rng.randint(10, 500),
                "after_hours_activity": self._rng.choice([True, False]),
            }

        elif category == AlertCategory.POLICY_VIOLATION:
            return {
                "policy_name": self._rng.choice(
                    [
                        "Software Installation Policy",
                        "Remote Access Policy",
                        "Data Classification Policy",
                        "Encryption Policy",
                        "Acceptable Use Policy",
                    ]
                ),
                "violation_type": self._rng.choice(
                    [
                        "unauthorized_app",
                        "config_drift",
                        "missing_encryption",
                        "unapproved_access",
                        "data_handling",
                    ]
                ),
                "compliance_framework": self._rng.choice(
                    AlertTemplates.POLICY_VIOLATION_TEMPLATES["frameworks"]
                ),
                "remediation_required": self._rng.choice([True, False]),
                "repeat_violation": self._rng.choice([True, False, False, False]),  # 25% repeat
                "software_name": (
                    self._rng.choice(
                        ["Dropbox", "TeamViewer", "AnyDesk", "Slack", "WhatsApp", "Unknown"]
                    )
                    if self._rng.random() > 0.5
                    else None
                ),
            }

        elif category == AlertCategory.VULNERABILITY_EXPLOIT:
            year = self._rng.randint(2020, 2024)
            cve_num = self._rng.randint(1000, 50000)
            return {
                "cve_id": f"CVE-{year}-{cve_num}",
                "cvss_score": round(self._rng.uniform(4.0, 10.0), 1),
                "cvss_vector": f"CVSS:3.1/AV:{self._rng.choice(['N', 'A', 'L'])}/AC:{self._rng.choice(['L', 'H'])}/PR:{self._rng.choice(['N', 'L', 'H'])}/UI:{self._rng.choice(['N', 'R'])}/S:{self._rng.choice(['U', 'C'])}/C:{self._rng.choice(['N', 'L', 'H'])}/I:{self._rng.choice(['N', 'L', 'H'])}/A:{self._rng.choice(['N', 'L', 'H'])}",
                "exploit_type": self._rng.choice(["remote", "local", "network", "web"]),
                "attack_type": self._rng.choice(
                    AlertTemplates.VULNERABILITY_TEMPLATES["attack_types"]
                ),
                "patch_available": self._rng.choice([True, True, True, False]),  # 75% have patches
                "affected_systems_count": self._rng.randint(1, 100),
                "exploit_successful": self._rng.choice([True, False]),
                "affected_service": self._rng.choice(
                    ["Apache", "Nginx", "IIS", "Tomcat", "Exchange", "SharePoint", "Custom"]
                ),
            }

        elif category == AlertCategory.RECONNAISSANCE:
            return {
                "scan_type": self._rng.choice(
                    [
                        "port_scan",
                        "vulnerability_scan",
                        "network_sweep",
                        "service_enumeration",
                        "os_fingerprinting",
                    ]
                ),
                "ports_scanned": self._rng.randint(10, 65535),
                "source_ip": self._generate_ip(),
                "duration_minutes": self._rng.randint(1, 120),
                "hosts_discovered": self._rng.randint(1, 100),
                "services_identified": self._rng.randint(0, 50),
                "scan_tool": self._rng.choice(
                    ["Nmap", "Masscan", "Nessus", "OpenVAS", "Custom", "Unknown"]
                ),
                "stealth_techniques": self._rng.choice([True, False]),
            }

        elif category == AlertCategory.DENIAL_OF_SERVICE:
            return {
                "attack_type": self._rng.choice(
                    ["volumetric", "protocol", "application_layer", "amplification"]
                ),
                "attack_vector": self._rng.choice(
                    [
                        "SYN Flood",
                        "UDP Flood",
                        "HTTP Flood",
                        "DNS Amplification",
                        "NTP Amplification",
                        "Slowloris",
                    ]
                ),
                "traffic_volume_gbps": round(self._rng.uniform(1, 500), 2),
                "packet_rate_mpps": round(self._rng.uniform(0.1, 100), 2),
                "source_ip_count": self._rng.randint(100, 1000000),
                "target_service": self._rng.choice(["web", "api", "dns", "database", "email"]),
                "target_port": self._rng.choice([80, 443, 53, 25, 3306]),
                "mitigation_active": self._rng.choice([True, False]),
                "duration_minutes": self._rng.randint(5, 480),
            }

        return {}

    def _determine_triage(
        self,
        category: AlertCategory,
        severity: Severity,
        indicators: dict[str, Any],
        user_context: UserContext,
        asset_context: AssetContext,
        environment_context: EnvironmentContext,
    ) -> TriageResponse:
        """Determine the appropriate triage response based on alert characteristics."""
        # Initialize base values
        priority = severity.priority_weight
        decision = TriageDecision.INVESTIGATE
        escalation_required = False
        confidence_score = 0.85
        key_factors = []
        actions = []
        additional_investigation = []
        ioc_extraction = []
        escalation_target = None
        estimated_urgency = "hours"
        estimated_impact = "moderate"

        # Critical severity always escalates
        if severity == Severity.CRITICAL:
            decision = TriageDecision.ESCALATE
            escalation_required = True
            estimated_impact = "severe"
            estimated_urgency = "immediate"
            key_factors.append("Critical severity requires immediate escalation")
            actions.append("Notify incident commander immediately")
            actions.append("Initiate incident response procedures")
            escalation_target = "Incident Response Team"

        # Category-specific logic
        if category == AlertCategory.MALWARE:
            if indicators.get("detection_method") == "signature":
                key_factors.append(
                    f"Known malware family detected: {indicators.get('malware_family', 'Unknown')}"
                )
                actions.append("Isolate affected endpoint from network")
                actions.append("Collect memory dump and forensic artifacts")
                ioc_extraction.append(f"File hash: {indicators.get('file_hash', '')[:32]}...")
            else:
                key_factors.append(
                    "Behavioral/heuristic detection may indicate new variant or false positive"
                )
                actions.append("Submit sample to sandbox for analysis")
                additional_investigation.append("Verify if file is part of legitimate software")

            if severity in [Severity.HIGH, Severity.CRITICAL]:
                decision = TriageDecision.ESCALATE
                escalation_required = True
                actions.append("Check for lateral movement indicators")
                actions.append("Review other endpoints for same hash")

        elif category == AlertCategory.PHISHING:
            if indicators.get("is_spoofed") or indicators.get("spf_result") == "fail":
                key_factors.append("Domain spoofing detected indicating targeted attack")
                decision = TriageDecision.INVESTIGATE
                actions.append("Identify all recipients of this email")
                actions.append("Block sender domain organization-wide")

            if len(indicators.get("malicious_urls", [])) > 0:
                ioc_extraction.extend(indicators.get("malicious_urls", [])[:3])
                actions.append("Block identified malicious URLs")

            if indicators.get("attachment_count", 0) > 0:
                actions.append("Analyze attachments in sandbox")
                additional_investigation.append("Check if any users opened attachments")

        elif category == AlertCategory.BRUTE_FORCE:
            if indicators.get("successful_auth"):
                decision = TriageDecision.ESCALATE
                escalation_required = True
                estimated_impact = "severe"
                estimated_urgency = "immediate"
                key_factors.append("CRITICAL: Successful authentication after brute force attack")
                actions.append("Force immediate password reset for affected accounts")
                actions.append("Revoke all active sessions")
                actions.append("Review recent account activity for unauthorized actions")
                escalation_target = "Security Operations Lead"
            elif indicators.get("failed_attempts", 0) > 100:
                key_factors.append(
                    f"High volume attack: {indicators.get('failed_attempts')} attempts detected"
                )
                actions.append("Block source IPs at firewall")
                if indicators.get("source_ip_count", 1) > 10:
                    key_factors.append("Distributed attack from multiple IPs suggests botnet")
            else:
                decision = TriageDecision.MONITOR
                key_factors.append("Low volume failed attempts - may be user error")
                actions.append("Monitor for continued attempts")

        elif category == AlertCategory.DATA_EXFILTRATION:
            volume = indicators.get("volume_mb", 0)
            classification = indicators.get("data_classification", "unknown")
            country = indicators.get("destination_country", "Unknown")

            if classification in ["confidential", "restricted"]:
                decision = TriageDecision.ESCALATE
                escalation_required = True
                key_factors.append(f"High sensitivity data ({classification}) transfer detected")
                escalation_target = "Data Protection Officer"

            if country in AlertTemplates.DATA_EXFILTRATION_TEMPLATES["high_risk_countries"]:
                decision = TriageDecision.ESCALATE
                escalation_required = True
                estimated_impact = "severe"
                key_factors.append(f"Data transfer to high-risk country: {country}")
                actions.append("Block data transfer immediately if ongoing")

            if volume > 10000:
                key_factors.append(f"Large data volume: {volume}MB transferred")

            actions.append("Preserve evidence for forensic investigation")
            actions.append("Identify all files involved in transfer")
            additional_investigation.append("Verify if transfer was authorized")

        elif category == AlertCategory.PRIVILEGE_ESCALATION:
            target_priv = indicators.get("target_privilege", "unknown")

            if target_priv in ["domain_admin", "enterprise_admin", "root"]:
                decision = TriageDecision.ESCALATE
                escalation_required = True
                estimated_impact = "severe"
                key_factors.append(f"Attempted escalation to highest privileges: {target_priv}")
                actions.append("Immediately contain affected system")
                actions.append("Audit all privileged account activity")
                escalation_target = "Incident Response Team"

            if indicators.get("success"):
                decision = TriageDecision.ESCALATE
                escalation_required = True
                key_factors.append("Privilege escalation was SUCCESSFUL")
                actions.append("Reset affected account credentials")

            actions.append("Check for persistence mechanisms")
            ioc_extraction.append(f"Technique: {indicators.get('mitre_technique', 'Unknown')}")

        elif category == AlertCategory.LATERAL_MOVEMENT:
            decision = TriageDecision.ESCALATE
            escalation_required = True
            estimated_impact = "severe"
            estimated_urgency = "immediate"
            key_factors.append("Lateral movement indicates active adversary in environment")
            key_factors.append(
                f"Movement to {indicators.get('destination_count', 1)} systems via {indicators.get('protocol', 'unknown')}"
            )
            actions.append("Map full scope of compromise")
            actions.append("Isolate source and destination systems")
            actions.append("Hunt for additional indicators across environment")
            actions.append("Preserve forensic evidence from all affected systems")
            escalation_target = "Incident Response Team"

        elif category == AlertCategory.COMMAND_AND_CONTROL:
            if indicators.get("threat_intel_match"):
                decision = TriageDecision.ESCALATE
                escalation_required = True
                estimated_impact = "severe"
                key_factors.append("Known malicious C2 infrastructure contacted")
                ioc_extraction.append(
                    f"C2 Domain: {indicators.get('destination_domain', 'Unknown')}"
                )
                if indicators.get("c2_framework") != "Unknown":
                    key_factors.append(f"C2 Framework identified: {indicators.get('c2_framework')}")
            else:
                key_factors.append("Suspicious beaconing pattern detected")
                additional_investigation.append("Verify if destination is legitimate service")

            actions.append("Isolate host immediately")
            actions.append("Block C2 domain/IP at perimeter")
            actions.append("Search for same beacon on other endpoints")

        elif category == AlertCategory.INSIDER_THREAT:
            risk_score = indicators.get("user_risk_score", 0)
            employment_status = indicators.get("employment_status", "active")

            if employment_status in ["notice_period", "terminated"]:
                decision = TriageDecision.ESCALATE
                escalation_required = True
                key_factors.append(f"High-risk user status: {employment_status}")
                actions.append("Coordinate with HR immediately")
                actions.append("Review all recent user activity")
                escalation_target = "HR and Legal"

            if risk_score > 80:
                key_factors.append(f"Elevated user risk score: {risk_score}/100")
                if user_context.is_vip:
                    escalation_target = "Executive Security"

            actions.append("Preserve evidence for potential investigation")
            additional_investigation.append("Compare activity with peer group baseline")

        elif category == AlertCategory.POLICY_VIOLATION:
            framework = indicators.get("compliance_framework", "")

            if framework in ["HIPAA", "PCI-DSS"]:
                decision = TriageDecision.INVESTIGATE
                key_factors.append(f"Regulatory compliance ({framework}) violation")
                actions.append("Document violation details thoroughly")
                actions.append("Notify compliance team")
                escalation_target = "Compliance Officer"
            elif framework in ["SOC2", "ISO27001"]:
                actions.append("Log violation for audit purposes")
                additional_investigation.append("Assess if violation impacts certification")
            else:
                decision = TriageDecision.MONITOR
                key_factors.append("Internal policy violation")
                actions.append("Notify user's manager")

        elif category == AlertCategory.VULNERABILITY_EXPLOIT:
            cvss = indicators.get("cvss_score", 0)
            exploit_success = indicators.get("exploit_successful", False)

            if exploit_success:
                decision = TriageDecision.ESCALATE
                escalation_required = True
                estimated_impact = "severe"
                key_factors.append("SUCCESSFUL EXPLOITATION DETECTED")
                actions.append("Isolate affected system immediately")
                actions.append("Check for post-exploitation activity")

            if cvss >= 9.0:
                key_factors.append(f"Critical vulnerability (CVSS {cvss})")
                if not indicators.get("patch_available"):
                    key_factors.append("No patch available - apply compensating controls")
                    actions.append("Implement network segmentation")
            elif cvss >= 7.0:
                key_factors.append(f"High severity vulnerability (CVSS {cvss})")

            ioc_extraction.append(f"CVE: {indicators.get('cve_id', 'Unknown')}")
            actions.append("Prioritize patching for affected systems")

        elif category == AlertCategory.RECONNAISSANCE:
            if environment_context.is_change_window:
                confidence_score -= 0.2
                key_factors.append("Activity during change window - may be authorized scan")
                additional_investigation.append("Verify with IT operations if scan is authorized")

            source_zone = "external"  # Would come from network context
            if source_zone == "external":
                key_factors.append("External reconnaissance - potential pre-attack activity")
                actions.append("Block source IP")
                actions.append("Review firewall rules")
            else:
                additional_investigation.append("Verify if internal security scan")
                # Higher chance of false positive for internal scans
                if self._rng.random() > 0.6:
                    decision = TriageDecision.FALSE_POSITIVE
                    key_factors = ["Appears to be authorized internal security scan"]
                    actions = ["Update detection rules to whitelist authorized scanners"]

        elif category == AlertCategory.DENIAL_OF_SERVICE:
            volume = indicators.get("traffic_volume_gbps", 0)

            if volume > 50:
                decision = TriageDecision.ESCALATE
                escalation_required = True
                estimated_impact = "severe"
                estimated_urgency = "immediate"
                key_factors.append(f"High volume attack: {volume} Gbps")
                actions.append("Engage DDoS mitigation service")
                actions.append("Notify affected service owners")
                escalation_target = "Network Operations"
            elif volume > 10:
                key_factors.append(f"Moderate attack volume: {volume} Gbps")
                actions.append("Monitor mitigation effectiveness")
            else:
                decision = TriageDecision.MONITOR
                key_factors.append("Low volume attack - automated mitigation may be sufficient")

        # Context-based adjustments
        if user_context.is_vip:
            priority = max(1, priority - 1)
            key_factors.append("VIP user involved - elevated priority")

        if asset_context.criticality == "critical":
            priority = max(1, priority - 1)
            key_factors.append("Critical asset affected - elevated priority")

        if asset_context.data_classification in ["confidential", "restricted"]:
            key_factors.append(f"Asset contains {asset_context.data_classification} data")

        if user_context.employment_status in ["notice_period", "terminated"]:
            key_factors.append(f"User employment status: {user_context.employment_status}")
            confidence_score = min(0.95, confidence_score + 0.1)

        if environment_context.is_change_window and decision != TriageDecision.FALSE_POSITIVE:
            confidence_score = max(0.5, confidence_score - 0.15)
            additional_investigation.append("Verify activity is not related to change window")

        if environment_context.threat_level in ["high", "critical"]:
            priority = max(1, priority - 1)
            key_factors.append(
                f"Elevated organization threat level: {environment_context.threat_level}"
            )

        # Small chance of false positive
        if self._rng.random() < 0.12 and decision not in [TriageDecision.ESCALATE]:
            decision = TriageDecision.FALSE_POSITIVE
            confidence_score = 0.88
            key_factors = ["Analysis indicates benign activity matching known patterns"]
            actions = ["Update detection rules to reduce false positives", "Document for tuning"]
            estimated_impact = "none"
            escalation_required = False
            additional_investigation = []

        # Build reasoning
        reasoning = " ".join(key_factors) if key_factors else "Standard triage procedures applied."

        return TriageResponse(
            decision=decision.value,
            priority=priority,
            confidence_score=round(confidence_score, 2),
            reasoning=reasoning,
            key_factors=key_factors[:5],
            recommended_actions=actions[:6],
            escalation_required=escalation_required,
            escalation_target=escalation_target,
            estimated_impact=estimated_impact,
            estimated_urgency=estimated_urgency,
            additional_investigation=additional_investigation[:3],
            ioc_extraction=ioc_extraction[:5],
        )

    def generate_alert(
        self,
        category: Optional[AlertCategory] = None,
        severity: Optional[Severity] = None,
    ) -> tuple[SecurityAlert, TriageResponse]:
        """Generate a single security alert with triage response.

        Args:
            category: Specific category (random if None)
            severity: Specific severity (random if None)

        Returns:
            Tuple of (SecurityAlert, TriageResponse)

        """
        self._alert_counter += 1

        # Random selection if not specified
        if category is None:
            category = self._rng.choice(list(AlertCategory))
        if severity is None:
            severity = self._rng.choices(list(Severity), weights=[0.05, 0.15, 0.40, 0.30, 0.10])[0]

        # Generate contexts
        user_context = self._generate_user_context()
        asset_context = self._generate_asset_context()
        network_context = self._generate_network_context(
            external_threat=category
            in [
                AlertCategory.RECONNAISSANCE,
                AlertCategory.DENIAL_OF_SERVICE,
                AlertCategory.BRUTE_FORCE,
            ]
        )
        environment_context = self._generate_environment_context()

        # Generate indicators
        indicators = self._generate_indicators(category)

        # Generate timestamp
        timestamp = (
            datetime.now()
            - timedelta(
                days=self._rng.randint(0, 30),
                hours=self._rng.randint(0, 23),
                minutes=self._rng.randint(0, 59),
            )
        ).isoformat()

        # Get template
        template_map = {
            AlertCategory.MALWARE: AlertTemplates.MALWARE_TEMPLATES,
            AlertCategory.PHISHING: AlertTemplates.PHISHING_TEMPLATES,
            AlertCategory.BRUTE_FORCE: AlertTemplates.BRUTE_FORCE_TEMPLATES,
            AlertCategory.DATA_EXFILTRATION: AlertTemplates.DATA_EXFILTRATION_TEMPLATES,
            AlertCategory.PRIVILEGE_ESCALATION: AlertTemplates.PRIVILEGE_ESCALATION_TEMPLATES,
            AlertCategory.LATERAL_MOVEMENT: AlertTemplates.LATERAL_MOVEMENT_TEMPLATES,
            AlertCategory.COMMAND_AND_CONTROL: AlertTemplates.C2_TEMPLATES,
            AlertCategory.INSIDER_THREAT: AlertTemplates.INSIDER_THREAT_TEMPLATES,
            AlertCategory.POLICY_VIOLATION: AlertTemplates.POLICY_VIOLATION_TEMPLATES,
            AlertCategory.VULNERABILITY_EXPLOIT: AlertTemplates.VULNERABILITY_TEMPLATES,
            AlertCategory.RECONNAISSANCE: AlertTemplates.RECONNAISSANCE_TEMPLATES,
            AlertCategory.DENIAL_OF_SERVICE: AlertTemplates.DOS_TEMPLATES,
        }

        template = template_map.get(category, AlertTemplates.MALWARE_TEMPLATES)
        source = self._rng.choice(template["sources"])

        # Format title with indicators
        title_template = self._rng.choice(template["titles"])
        try:
            title = title_template.format(
                **{
                    **indicators,
                    "department": user_context.department,
                    "source": network_context.source_ip,
                    "count": indicators.get("failed_attempts", self._rng.randint(10, 100)),
                    "source_count": indicators.get("source_ip_count", self._rng.randint(1, 50)),
                    "source_ip": network_context.source_ip,
                    "target_count": indicators.get("destination_count", self._rng.randint(1, 10)),
                    "target": asset_context.hostname,
                    "interval": indicators.get("beacon_interval_seconds", 60),
                    "domain": indicators.get("destination_domain", "unknown.com"),
                    "port": indicators.get("target_port", 443),
                    "volume": indicators.get(
                        "volume_mb", indicators.get("traffic_volume_gbps", 100)
                    ),
                    "sender_domain": indicators.get("sender_email", "unknown@unknown.com").split(
                        "@"
                    )[-1],
                    "file_type": (
                        self._rng.choice(indicators.get("attachment_types", [".pdf"]))
                        if indicators.get("attachment_types")
                        else ".pdf"
                    ),
                    "brand": self._rng.choice(
                        ["Microsoft", "Google", "Apple", "Amazon", "LinkedIn"]
                    ),
                    "user": user_context.username,
                    "score": indicators.get("user_risk_score", 75),
                    "resource": self._rng.choice(
                        ["Finance Share", "HR Database", "Executive Folder", "Source Code"]
                    ),
                    "technique": indicators.get("technique", "unknown"),
                    "method": self._rng.choice(["fodhelper", "eventvwr", "sdclt"]),
                    "cve": indicators.get("cve_id", "CVE-2024-0000"),
                    "attack_type": indicators.get("attack_type", "SQL Injection"),
                    "service": indicators.get("affected_service", "web server"),
                    "software": indicators.get("software_name", "unknown application"),
                    "app": indicators.get("software_name", "shadow application"),
                    "region": self._rng.choice(["EU", "China", "Russia"]),
                    "asset": asset_context.hostname,
                    "malware_family": indicators.get("malware_family", "Unknown"),
                    "ports": indicators.get("ports_scanned", 1000),
                }
            )
        except KeyError:
            title = (
                title_template.split("{")[0].strip() if "{" in title_template else title_template
            )

        # Build description
        description = f"{title}. "
        description += f"Detected by {source} on {asset_context.hostname}. "
        description += f"Affected user: {user_context.username} ({user_context.department}, {user_context.role}). "
        description += f"Asset criticality: {asset_context.criticality}. "
        description += f"User risk level: {user_context.risk_level}."

        # Generate raw log
        raw_log = self._generate_raw_log(category, indicators, timestamp)

        # Build alert
        alert = SecurityAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=timestamp,
            source_system=source,
            category=category.value,
            severity=severity.value,
            title=title,
            description=description,
            affected_assets=[asset_context.hostname],
            indicators=indicators,
            user_context=asdict(user_context),
            asset_context=asdict(asset_context),
            network_context=asdict(network_context),
            environment_context=asdict(environment_context),
            raw_log=raw_log,
            mitre_techniques=category.mitre_tactics,
        )

        # Generate triage response
        triage = self._determine_triage(
            category, severity, indicators, user_context, asset_context, environment_context
        )

        return alert, triage

    def format_for_training(
        self,
        alert: SecurityAlert,
        triage: TriageResponse,
        format_type: str = "chat",
    ) -> dict[str, Any]:
        """Format alert-triage pair for model training.

        Args:
            alert: The security alert
            triage: The triage response
            format_type: One of "chat", "instruction", "completion", "sharegpt"

        Returns:
            Formatted training example

        """
        system_message = """You are an expert Security Operations Center (SOC) analyst AI assistant. Your role is to analyze security alerts and provide comprehensive triage recommendations. For each alert, you should:

1. Assess the severity and potential impact based on all available context
2. Determine the appropriate triage decision (escalate, investigate, monitor, false_positive, or close)
3. Assign a priority level (1=highest/immediate, 5=lowest)
4. Provide clear, actionable reasoning for your decision
5. Recommend specific remediation and investigation actions
6. Identify indicators of compromise (IOCs) for threat hunting
7. Determine if escalation is required and to whom

Consider the full context including:
- User information (role, department, VIP status, employment status)
- Asset criticality and data classification
- Environmental factors (business hours, change windows, threat level)
- Historical patterns and related alerts

Provide your response in a structured format that can be easily parsed and actioned by the SOC team."""

        user_message = f"""Analyze the following security alert and provide a comprehensive triage recommendation:

## Alert Details
- **Alert ID:** {alert.alert_id}
- **Timestamp:** {alert.timestamp}
- **Source System:** {alert.source_system}
- **Category:** {alert.category}
- **Severity:** {alert.severity}

## Alert Information
**Title:** {alert.title}

**Description:** {alert.description}

**Affected Assets:** {', '.join(alert.affected_assets)}

**MITRE ATT&CK Tactics:** {', '.join(alert.mitre_techniques) if alert.mitre_techniques else 'Not mapped'}

## Indicators of Compromise
```json
{json.dumps(alert.indicators, indent=2)}
```

## Context Information

### User Context
- **Username:** {alert.user_context.get('username', 'N/A')}
- **Department:** {alert.user_context.get('department', 'N/A')}
- **Role:** {alert.user_context.get('role', 'N/A')}
- **Risk Level:** {alert.user_context.get('risk_level', 'N/A')}
- **VIP Status:** {'Yes' if alert.user_context.get('is_vip') else 'No'}
- **Employment Status:** {alert.user_context.get('employment_status', 'N/A')}
- **Previous Incidents:** {alert.user_context.get('previous_incidents', 0)}

### Asset Context
- **Hostname:** {alert.asset_context.get('hostname', 'N/A')}
- **Asset Type:** {alert.asset_context.get('asset_type', 'N/A')}
- **Criticality:** {alert.asset_context.get('criticality', 'N/A')}
- **Data Classification:** {alert.asset_context.get('data_classification', 'N/A')}
- **Operating System:** {alert.asset_context.get('operating_system', 'N/A')}
- **Patch Status:** {alert.asset_context.get('patch_status', 'N/A')}

### Environment Context
- **Business Hours:** {'Yes' if alert.environment_context.get('is_business_hours') else 'No'}
- **Change Window:** {'Yes' if alert.environment_context.get('is_change_window') else 'No'}
- **Organization Threat Level:** {alert.environment_context.get('threat_level', 'normal')}
- **Active Incidents:** {alert.environment_context.get('active_incidents', 0)}

## Raw Log Entry
```
{alert.raw_log}
```

Provide your triage recommendation with decision, priority, reasoning, and specific actions."""

        assistant_message = f"""## Triage Recommendation

### Decision Summary
| Field | Value |
|-------|-------|
| **Decision** | {triage.decision.upper()} |
| **Priority** | {triage.priority}/5 |
| **Confidence** | {triage.confidence_score * 100:.0f}% |
| **Escalation Required** | {'Yes' if triage.escalation_required else 'No'} |
| **Escalation Target** | {triage.escalation_target or 'N/A'} |
| **Estimated Impact** | {triage.estimated_impact.title()} |
| **Estimated Urgency** | {triage.estimated_urgency.title()} |

### Key Factors
{chr(10).join(f"- {factor}" for factor in triage.key_factors) if triage.key_factors else "- Standard triage procedures applied"}

### Reasoning
{triage.reasoning}

### Recommended Actions
{chr(10).join(f"{i+1}. {action}" for i, action in enumerate(triage.recommended_actions))}

### Additional Investigation Required
{chr(10).join(f"- {item}" for item in triage.additional_investigation) if triage.additional_investigation else "- No additional investigation required at this time"}

### Indicators of Compromise (IOCs) for Threat Hunting
{chr(10).join(f"- {ioc}" for ioc in triage.ioc_extraction) if triage.ioc_extraction else "- No specific IOCs extracted"}

### Summary
This **{alert.severity}** severity **{alert.category.replace('_', ' ')}** alert {"requires immediate escalation to " + (triage.escalation_target or "the security team") if triage.escalation_required else "can be handled through standard procedures"}. The affected asset ({alert.asset_context.get('hostname', 'unknown')}) has **{alert.asset_context.get('criticality', 'unknown')}** criticality{" and involves a VIP user, warranting elevated attention" if alert.user_context.get('is_vip') else ""}. {"The organization is currently at elevated threat level, which should factor into response prioritization." if alert.environment_context.get('threat_level') in ['high', 'critical'] else ""}"""

        if format_type == "chat":
            return {
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message},
                    {"role": "assistant", "content": assistant_message},
                ]
            }
        elif format_type == "sharegpt":
            return {
                "conversations": [
                    {"from": "system", "value": system_message},
                    {"from": "human", "value": user_message},
                    {"from": "gpt", "value": assistant_message},
                ]
            }
        elif format_type == "instruction":
            return {
                "instruction": system_message,
                "input": user_message,
                "output": assistant_message,
            }
        elif format_type == "completion":
            return {
                "prompt": f"{system_message}\n\nUser: {user_message}\n\nAssistant:",
                "completion": assistant_message,
            }
        elif format_type == "huggingface":
            return {
                "text": f"<|system|>\n{system_message}\n<|user|>\n{user_message}\n<|assistant|>\n{assistant_message}",
                "system": system_message,
                "user": user_message,
                "assistant": assistant_message,
            }
        else:
            raise ValueError(f"Unknown format type: {format_type}")

    def generate_dataset(
        self,
        num_samples: int = 1000,
        format_type: str = "chat",
        include_metadata: bool = False,
        balanced: bool = True,
    ) -> list[dict[str, Any]]:
        """Generate a complete training dataset.

        Args:
            num_samples: Number of samples to generate
            format_type: Output format ("chat", "instruction", "completion", "sharegpt", "huggingface")
            include_metadata: Whether to include raw alert/triage data
            balanced: Whether to balance across categories

        Returns:
            List of formatted training examples

        """
        samples = []

        if balanced:
            # Generate roughly equal samples per category
            categories = list(AlertCategory)
            samples_per_category = num_samples // len(categories)
            remainder = num_samples % len(categories)

            for i, category in enumerate(categories):
                count = samples_per_category + (1 if i < remainder else 0)
                for _ in range(count):
                    alert, triage = self.generate_alert(category=category)
                    formatted = self.format_for_training(alert, triage, format_type)

                    if include_metadata:
                        formatted["_metadata"] = {
                            "alert": alert.to_dict(),
                            "triage": triage.to_dict(),
                        }

                    samples.append(formatted)
        else:
            for _ in range(num_samples):
                alert, triage = self.generate_alert()
                formatted = self.format_for_training(alert, triage, format_type)

                if include_metadata:
                    formatted["_metadata"] = {
                        "alert": alert.to_dict(),
                        "triage": triage.to_dict(),
                    }

                samples.append(formatted)

        self._rng.shuffle(samples)
        return samples

    def save_dataset(
        self,
        samples: list[dict[str, Any]],
        output_path: str,
        format: str = "jsonl",
    ) -> None:
        """Save dataset to file.

        Args:
            samples: List of training samples
            output_path: Output file path
            format: File format ("jsonl", "json", "parquet")

        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if format == "jsonl":
            with open(path, "w") as f:
                for sample in samples:
                    f.write(json.dumps(sample) + "\n")
        elif format == "json":
            with open(path, "w") as f:
                json.dump(samples, f, indent=2)
        elif format == "parquet":
            try:
                import pandas as pd

                df = pd.DataFrame(samples)
                df.to_parquet(path)
            except ImportError as err:
                raise ImportError("pandas and pyarrow required for parquet format") from err
        else:
            raise ValueError(f"Unknown format: {format}")

    def get_statistics(self, samples: list[dict[str, Any]]) -> dict[str, Any]:
        """Calculate statistics for a generated dataset.

        Args:
            samples: List of training samples with metadata

        Returns:
            Dictionary of statistics

        """
        categories: dict[str, int] = {}
        severities: dict[str, int] = {}
        decisions: dict[str, int] = {}
        stats: dict[str, Any] = {
            "total_samples": len(samples),
            "categories": categories,
            "severities": severities,
            "decisions": decisions,
            "avg_prompt_length": 0,
            "avg_completion_length": 0,
        }

        total_prompt_len = 0
        total_completion_len = 0

        for sample in samples:
            if "_metadata" in sample:
                alert = sample["_metadata"]["alert"]
                triage = sample["_metadata"]["triage"]

                cat = alert.get("category", "unknown")
                sev = alert.get("severity", "unknown")
                dec = triage.get("decision", "unknown")

                categories[cat] = categories.get(cat, 0) + 1
                severities[sev] = severities.get(sev, 0) + 1
                decisions[dec] = decisions.get(dec, 0) + 1

            if "messages" in sample:
                user_msg = sample["messages"][1]["content"]
                assistant_msg = sample["messages"][2]["content"]
                total_prompt_len += len(user_msg.split())
                total_completion_len += len(assistant_msg.split())

        if samples:
            stats["avg_prompt_length"] = total_prompt_len // len(samples)
            stats["avg_completion_length"] = total_completion_len // len(samples)

        return stats


def main():
    """Generate sample dataset for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate synthetic security alert data")
    parser.add_argument("--num-samples", type=int, default=1000, help="Number of samples")
    parser.add_argument(
        "--format",
        choices=["chat", "instruction", "completion", "sharegpt", "huggingface"],
        default="chat",
        help="Output format",
    )
    parser.add_argument("--output", type=str, default="data/train.jsonl", help="Output file")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--balanced", action="store_true", help="Balance across categories")
    parser.add_argument("--include-metadata", action="store_true", help="Include metadata")

    args = parser.parse_args()

    generator = SecurityAlertGenerator(seed=args.seed)

    print(f"Generating {args.num_samples} samples...")
    samples = generator.generate_dataset(
        num_samples=args.num_samples,
        format_type=args.format,
        include_metadata=args.include_metadata,
        balanced=args.balanced,
    )

    generator.save_dataset(samples, args.output)
    print(f"Saved to {args.output}")

    if args.include_metadata:
        stats = generator.get_statistics(samples)
        print("\nDataset Statistics:")
        print(f"  Total samples: {stats['total_samples']}")
        print(f"  Avg prompt length: {stats['avg_prompt_length']} words")
        print(f"  Avg completion length: {stats['avg_completion_length']} words")


if __name__ == "__main__":
    main()
