from langchain_groq import ChatGroq
from app.agents.state import SOCState
from app.rag.retrieval import retrieve
from app.config import get_settings
import json

settings = get_settings()


def triage_agent(state: SOCState) -> SOCState:
    """
    Agent Triage : classifie l'incident et évalue la sévérité.
    Utilise le RAG CAPEC + ATT&CK pour contextualiser.
    """

    print("[Triage] Starting classification...")

    # 1. RAG — Chercher sur une portion plus large ou complète du log pour capter LockBit et les CVEs
    # On passe le log complet (ou les 2000 premiers caractères) pour ne rien rater
    rag_results = retrieve(state["raw_log"][:2000], top_k=3)
    
    rag_context = "\n".join([
        f"- [{r['metadata'].get('source','').upper()}] "
        f"{r['metadata'].get('technique','')} : "
        f"{r['content'][:200]}"
        for r in rag_results
    ])

    # 2. Construire le prompt
    prompt = f"""You are a SOC analyst specializing in insurance sector security.

Analyze this security incident log and classify it.

=== INCIDENT LOG ===
{state['raw_log']}

=== RELEVANT KNOWLEDGE BASE ===
{rag_context}

=== ENRICHED IOCs ===
{json.dumps(state.get('enrichment', {}), indent=2)}

Respond ONLY with a valid JSON object (no markdown, no explanation):
{{
    "incident_type": "string (e.g. Phishing, Brute Force, Account Takeover, Data Exfiltration)",
    "severity": integer from 1 to 10,
    "urgency": "immediate | high | medium | low",
    "evidence": ["list", "of", "concrete", "observations", "from", "the", "log"],
    "reasoning": "brief explanation of your classification"
}}"""

    # 3. Appel LLM
    llm = ChatGroq(
        api_key=settings.GROQ_API_KEY,
        model="llama-3.3-70b-versatile",
        temperature=0
    )

    response = llm.invoke(prompt)
    raw = response.content.strip()

    # 4. Parser la réponse JSON
    try:
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw)
    except Exception as e:
        print(f"[Triage] JSON parse error: {e}")
        result = {
            "incident_type": "Unknown",
            "severity": 5,
            "urgency": "medium",
            "evidence": ["Parse error"],
            "reasoning": raw
        }

    print(f"[Triage] → {result['incident_type']} | Severity: {result['severity']}/10")

    # 5. Mettre à jour l'état (On ajoute enfin rag_chunks_used pour l'API !)
    return {
        **state,
        "incident_type": result.get("incident_type", "Unknown"),
        "severity": result.get("severity", 5),
        "urgency": result.get("urgency", "medium"),
        "triage_evidence": result.get("evidence", []),
        "rag_chunks_used": rag_results  # <-- Crucial pour que le JSON final ne soit plus vide !
    }