from langgraph.graph import StateGraph, END
from app.agents.state import SOCState
from app.agents.triage import triage_agent
from app.agents.mapping import mapping_agent
from app.agents.killchain import killchain_agent
from app.agents.remediation import remediation_agent

# === IMPORTS AJOUTÉS ET VÉRIFIÉS ===
from app.sanitization.sanitizer import DataSanitizer
from app.services.scoring import ScoringService  # Évite le NameError

def build_pipeline():
    """
    Construit le graphe LangGraph avec les 4 agents en séquence.
    """
    graph = StateGraph(SOCState)

    # Ajouter les nœuds
    graph.add_node("triage", triage_agent)
    graph.add_node("mapping", mapping_agent)
    graph.add_node("killchain", killchain_agent)
    graph.add_node("remediation", remediation_agent)

    # Définir le flux séquentiel
    graph.set_entry_point("triage")
    graph.add_edge("triage", "mapping")
    graph.add_edge("mapping", "killchain")
    graph.add_edge("killchain", "remediation")
    graph.add_edge("remediation", END)

    return graph.compile()

# Instance globale du graphe
soc_pipeline = build_pipeline()

def run_analysis(raw_log: str, incident_id: str = "INC-001", enrichment: dict = {}) -> SOCState:
    """
    Point d'entrée unique du SOC AI :
    1. Reçoit le log brut, le nettoie (Sanitization) et extrait les IOCs.
    2. Injecte l'enrichissement IOC (VirusTotal, AbuseIPDB...) s'il est fourni.
    3. Exécute le pipeline multi-agents sur ces données validées.
    4. Calcule le score de confiance final.
    """
    print(f"\n[Pipeline] Initializing analysis for {incident_id}...")
    
    # 1. Traitement de la Sanitization & Extraction des IOCs internes
    sanitized_log, extracted_iocs = DataSanitizer.extract_and_sanitize(raw_log)
    print(f"[Pipeline] Sanitization complete. Extracted {len(extracted_iocs)} internal IOCs/Entities.")

    # 2. Configuration de l'état de départ avec le log nettoyé et l'enrichissement
    initial_state: SOCState = {
        "raw_log": sanitized_log,       # Les agents reçoivent le log APRES sanitization
        "incident_id": incident_id,
        "iocs": extracted_iocs,         # Liste des vrais IOCs isolés en sécurité
        "enrichment": enrichment,       # Reçoit les données de VirusTotal / AbuseIPDB passées en paramètre
        "incident_type": None,
        "severity": None,
        "urgency": None,
        "triage_evidence": [],
        "mitre_techniques": [],
        "kill_chain": [],
        "kill_chain_narrative": None,
        "remediation": None,
        "confidence_score": None,
        "rag_chunks_used": [],
    }

    # 3. Lancement des agents LangGraph
    result = soc_pipeline.invoke(initial_state)
    
    # 4. Calcul déterministe du score de confiance global
    # (ScoringService analyse maintenant les techniques trouvées + les scores de l'enrichissement)
    result["confidence_score"] = ScoringService.calculate_confidence(result)
    print(f"[Pipeline] Confidence Score successfully computed: {result['confidence_score']}/1.0")
    
    return result