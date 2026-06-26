from langgraph.graph import StateGraph, END
from app.agents.state import SOCState
from app.agents.triage import triage_agent
from app.agents.mapping import mapping_agent
from app.agents.killchain import killchain_agent
from app.agents.remediation import remediation_agent

# === IMPORTS AJOUTÉS ET VÉRIFIÉS ===
from app.sanitization.sanitizer import DataSanitizer
from app.services.scoring import ScoringService  
from app.enrichment.ioc_service import enrich_ioc  # <-- Importation de ton service OSINT

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

# ⚠️ La fonction doit être 'async def' pour pouvoir utiliser 'await' sur enrich_ioc !
async def run_analysis(raw_log: str, incident_id: str = "INC-001", enrichment: dict = {}) -> SOCState:
    """
    Point d'entrée unique du SOC AI :
    1. Reçoit le log brut, le nettoie (Sanitization) et extrait les IOCs.
    2. Si aucun enrichissement n'est fourni, interroge dynamiquement les APIs (VT, AbuseIPDB, OTX).
    3. Exécute le pipeline multi-agents sur ces données validées.
    4. Calcule le score de confiance final.
    """
    print(f"\n[Pipeline] Initializing analysis for {incident_id}...")
    
    # 1. Traitement de la Sanitization & Extraction des IOCs internes
    sanitized_log, extracted_iocs = DataSanitizer.extract_and_sanitize(raw_log)
    print(f"[Pipeline] Sanitization complete. Extracted {len(extracted_iocs)} internal IOCs/Entities.")

    # 2. Enrichissement automatique si le dictionnaire fourni est vide
    auto_enrichment = dict(enrichment)
    if not auto_enrichment and extracted_iocs:
        print(f"[Pipeline] Triggering parallel OSINT enrichment for extracted IOCs...")
        for ioc in extracted_iocs:
            # On n'enrichit que les types pertinents pris en charge par ton ioc_service
            if ioc.get("type") in ["ip", "domain", "hash"]:
                try:
                    val = ioc.get("value")
                    print(f"[Pipeline] Enriching {ioc['type']}: {val}...")
                    # Interrogation parallèle asynchrone
                    res = await enrich_ioc(ioc["type"], val)
                    auto_enrichment[val] = res
                except Exception as e:
                    print(f"[Pipeline] Error enriching {ioc.get('value')}: {e}")

    # 3. Configuration de l'état de départ avec le log nettoyé et l'enrichissement consolidé
    initial_state: SOCState = {
        "raw_log": sanitized_log,       
        "incident_id": incident_id,
        "iocs": extracted_iocs,         
        "enrichment": auto_enrichment,  # <-- Les agents et le Triage reçoivent enfin l'OSINT !
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

    # 4. Lancement des agents LangGraph
    result = soc_pipeline.invoke(initial_state)
    
    # 5. Calcul déterministe du score de confiance global
    result["confidence_score"] = ScoringService.calculate_confidence(result)
    print(f"[Pipeline] Confidence Score successfully computed: {result['confidence_score']}/1.0")
    
    return result