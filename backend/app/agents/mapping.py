from langchain_groq import ChatGroq
from app.agents.state import SOCState
from app.rag.retrieval import retrieve
from app.config import get_settings
import json

settings = get_settings()


def mapping_agent(state: SOCState) -> SOCState:
    """
    Agent Mapping : identifie les techniques MITRE ATT&CK.
    Utilise le RAG ATT&CK complet.
    """

    print("[Mapping] Starting ATT&CK mapping...")

    # 1. RAG — chercher les techniques ATT&CK pertinentes
    query = f"{state.get('incident_type', '')} {state['raw_log'][:150]}"
    rag_results = retrieve(query, top_k=5)
    rag_context = "\n".join([
        f"- {r['metadata'].get('technique','')} "
        f"{r['metadata'].get('title', r['content'][:100])}"
        for r in rag_results
        if r['metadata'].get('source') == 'attack'
    ])

    prompt = f"""You are a MITRE ATT&CK expert analyst.

Incident Type: {state.get('incident_type')}
Severity: {state.get('severity')}/10

=== LOG ===
{state['raw_log']}

=== RELEVANT ATT&CK TECHNIQUES ===
{rag_context}

=== OBSERVED EVIDENCE ===
{json.dumps(state.get('triage_evidence', []))}

Map this incident to MITRE ATT&CK techniques.
Respond ONLY with valid JSON:
{{
    "techniques": [
        {{
            "id": "T1566.001",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "confidence": 0.92,
            "evidence": ["specific log line or observation that proves this technique"]
        }}
    ]
}}"""

    llm = ChatGroq(
        api_key=settings.GROQ_API_KEY,
        model="llama-3.3-70b-versatile",
        temperature=0
    )

    response = llm.invoke(prompt)
    raw = response.content.strip()

    try:
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw)
    except Exception as e:
        print(f"[Mapping] JSON parse error: {e}")
        result = {"techniques": []}

    techniques = result.get("techniques", [])
    print(f"[Mapping] → {len(techniques)} techniques identified")
    for t in techniques:
        print(f"  {t.get('id')} - {t.get('name')} (confidence: {t.get('confidence')})")

    return {
        **state,
        "mitre_techniques": techniques,
    }