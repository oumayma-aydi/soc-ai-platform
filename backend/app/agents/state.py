from typing import TypedDict, List, Optional, Dict, Any


class SOCState(TypedDict):
    """
    État partagé entre tous les agents LangGraph.
    Chaque agent lit ce dont il a besoin et ajoute ses résultats.
    """

    # === INPUT ===
    raw_log: str                          # log brut soumis par l'analyste
    incident_id: str                      # identifiant unique

    # === IOC ENRICHMENT ===
    iocs: List[Dict[str, Any]]           # IOCs extraits du log
    enrichment: Dict[str, Any]           # résultats VirusTotal/AbuseIPDB/OTX

    # === AGENT TRIAGE ===
    incident_type: Optional[str]         # "Phishing", "Brute Force", etc.
    severity: Optional[int]              # 1-10
    urgency: Optional[str]               # "immediate" / "high" / "medium" / "low"
    triage_evidence: List[str]           # preuves observées

    # === AGENT MAPPING ===
    mitre_techniques: List[Dict[str, Any]]  # [{id, name, confidence, evidence}]

    # === AGENT KILL CHAIN ===
    kill_chain: List[Dict[str, Any]]     # [{timestamp, phase, technique, description}]
    kill_chain_narrative: Optional[str]  # narration chronologique

    # === AGENT REMEDIATION ===
    remediation: Optional[Dict[str, Any]]  # actions structurées + détections

    # === SCORING ===
    confidence_score: Optional[float]    # 0.0 - 1.0

    # === RAG ===
    rag_chunks_used: List[str]           # IDs des chunks RAG utilisés