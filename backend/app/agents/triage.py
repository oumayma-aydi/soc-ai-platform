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
    rag_results = retrieve(state["raw_log"][:2000], top_k=8)

    # Séparer par source pour un contexte structuré, comme dans mapping.py
    attack_chunks = [r for r in rag_results if r['metadata'].get('source') == 'attack']
    capec_chunks = [r for r in rag_results if r['metadata'].get('source') == 'capec']
    cisa_chunks = [r for r in rag_results if r['metadata'].get('source') == 'cisa']

    rag_context = ""
    if attack_chunks:
        rag_context += "=== MITRE ATT&CK TECHNIQUES ===\n"
        rag_context += "\n".join([f"- {r['metadata'].get('technique','')}: {r['content'][:200]}" for r in attack_chunks])
    if capec_chunks:
        rag_context += "\n=== CAPEC ATTACK PATTERNS ===\n"
        rag_context += "\n".join([f"- {r['metadata'].get('technique','')}: {r['content'][:200]}" for r in capec_chunks])
    if cisa_chunks:
        rag_context += "\n=== CISA KNOWN EXPLOITED VULNERABILITIES ===\n"
        rag_context += "\n".join([f"- {r['metadata'].get('technique','')}: {r['content'][:200]}" for r in cisa_chunks])

    # 2. Construire le prompt
    prompt = f"""You are a SOC analyst specializing in insurance sector security.

Analyze this security incident log and classify it.

=== INCIDENT LOG ===
{state['raw_log']}

=== RELEVANT KNOWLEDGE BASE ===
{rag_context}

=== ENRICHED IOCs ===
{json.dumps(state.get('enrichment', {}), indent=2)}

IMPORTANT: Base your "incident_type" classification on the actual evidence in the
log AND the retrieved knowledge base context above (MITRE ATT&CK, CAPEC, CISA).
If the log shows scanning, probing, or fingerprinting activity — even without a
successful exploit — this is a legitimate, classifiable incident (e.g.
"Reconnaissance" or the closest matching CAPEC attack pattern name). Only use
"incident_type": "Unknown" if the log truly contains no security-relevant
activity at all. Do not default to "Unknown" just because the incident seems
minor or the classification is not perfectly clear-cut — use your best-supported
judgment based on the evidence and knowledge base provided.

IMPORTANT: If you need to quote a Windows file path in your response (e.g.
\\SERVER\share\folder), you MUST escape every backslash as \\\\ in the JSON
output, or better, describe the path in plain words instead of copying it
literally (e.g. "the shared folder on FILESERVER01").

=== EVIDENCE CERTAINTY LANGUAGE (MUST FOLLOW) ===
Distinguish clearly between what is directly evidenced in the log versus what is
inferred or assumed. Use precise hedging language:
- "Confirmed" / definitive verbs (executed, detected, established) — ONLY when
  the log directly and unambiguously shows this happened.
- "Likely" / "Evidence suggests" / "Possibly" — when reasonably inferred but not
  directly observed (e.g. inferring intent from a partial IOC match).
- "Could not be confirmed" / "Unknown from available telemetry" — for any
  standard attack element (e.g. initial access vector, persistence mechanism,
  data actually exfiltrated vs. connection merely established) that the log
  does NOT provide direct evidence for. Do not silently omit these gaps.
Never state something as fact if it is actually an assumption.

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

    # 4. Parser la réponse JSON (avec réparation automatique des backslashes non échappés)
    from app.agents.json_utils import parse_llm_json
    try:
        result = parse_llm_json(raw)
    except Exception as e:
        print(f"[Triage] JSON parse error (unrecoverable): {e}")
        print(f"[Triage] Raw response was: {raw[:500]}")
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