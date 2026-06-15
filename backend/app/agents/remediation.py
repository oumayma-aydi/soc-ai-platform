from langchain_groq import ChatGroq
from app.agents.state import SOCState
from app.rag.retrieval import retrieve
from app.config import get_settings
import json

settings = get_settings()


def remediation_agent(state: SOCState) -> SOCState:
    """
    Agent Remediation : génère des recommandations structurées.
    Utilise D3FEND + CISA + OWASP depuis le RAG.
    C'est le cœur du projet.
    """

    print("[Remediation] Generating structured recommendations...")

    # 1. RAG — chercher D3FEND + CISA + OWASP
    query = f"remediation {state.get('incident_type')} {' '.join([t.get('id','') for t in state.get('mitre_techniques',[])])}"
    
    rag_results = retrieve(query, top_k=8)
    
    # Séparer par source
    d3fend_chunks = [r for r in rag_results if r['metadata'].get('source') == 'd3fend']
    cisa_chunks = [r for r in rag_results if r['metadata'].get('source') == 'cisa']
    owasp_chunks = [r for r in rag_results if r['metadata'].get('source') == 'owasp']

    rag_context = ""
    if d3fend_chunks:
        rag_context += "=== D3FEND COUNTERMEASURES ===\n"
        rag_context += "\n".join([f"- {r['metadata'].get('title','')}: {r['content'][:200]}" for r in d3fend_chunks])
    if cisa_chunks:
        rag_context += "\n=== CISA ADVISORIES ===\n"
        rag_context += "\n".join([f"- {r['metadata'].get('technique','')}: {r['content'][:200]}" for r in cisa_chunks])
    if owasp_chunks:
        rag_context += "\n=== OWASP GUIDANCE ===\n"
        rag_context += "\n".join([f"- {r['metadata'].get('title','')}: {r['content'][:200]}" for r in owasp_chunks])

    techniques_str = ", ".join([
        f"{t.get('id')} {t.get('name')}"
        for t in state.get("mitre_techniques", [])
    ])

    prompt = f"""You are a senior SOC analyst at an insurance company.
Generate structured remediation actions for this security incident.

=== INCIDENT SUMMARY ===
Type: {state.get('incident_type')}
Severity: {state.get('severity')}/10
Urgency: {state.get('urgency')}
ATT&CK Techniques: {techniques_str}

=== ATTACK NARRATIVE ===
{state.get('kill_chain_narrative', '')}

=== KNOWLEDGE BASE (D3FEND + CISA + OWASP) ===
{rag_context}

=== ENRICHED IOCs ===
{json.dumps(state.get('enrichment', {}), indent=2)[:500]}

Generate actionable remediation for the SOC team.
Respond ONLY with valid JSON:
{{
    "actions": [
        {{
            "priority": 1,
            "timeframe": "immediate < 15min",
            "action": "Specific action to take",
            "how": "Step by step instructions",
            "source": "D3FEND/CISA/OWASP reference"
        }},
        {{
            "priority": 2,
            "timeframe": "urgent < 1h",
            "action": "...",
            "how": "...",
            "source": "..."
        }},
        {{
            "priority": 3,
            "timeframe": "short term < 24h",
            "action": "...",
            "how": "...",
            "source": "..."
        }}
    ],
    "detections_to_deploy": [
        "SIEM rule or detection to add"
    ],
    "summary": "One paragraph executive summary of what happened and what to do"
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
        print(f"[Remediation] JSON parse error: {e}")
        result = {"actions": [], "detections_to_deploy": [], "summary": raw}

    actions = result.get("actions", [])
    print(f"[Remediation] → {len(actions)} actions generated")
    for a in actions:
        print(f"  P{a.get('priority')} [{a.get('timeframe')}] {a.get('action','')[:60]}")

    return {
        **state,
        "remediation": result,
    }