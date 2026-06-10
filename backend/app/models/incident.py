from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class IOC(BaseModel):
    """
    IOC = Indicator of Compromise
    ex: IP, domain, hash
    """
    type: str  # ip / domain / hash
    value: str
    source: Optional[str] = None  # VirusTotal / OTX / AbuseIPDB


class Incident(BaseModel):
    """
    Représente un incident SOC complet entrant dans le pipeline IA
    """

    id: Optional[str] = None

    # raw log from SIEM
    raw_log: str

    # time of detection
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # enriched IOCs
    iocs: List[IOC] = []

    # result from triage agent
    severity: Optional[int] = None  # 1-10
    incident_type: Optional[str] = None

    # MITRE mapping
    mitre_techniques: List[str] = []

    # kill chain steps
    kill_chain: List[str] = []

    # final remediation output
    remediation: Optional[dict] = None