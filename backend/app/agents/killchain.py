from langchain_groq import ChatGroq
from app.agents.state import SOCState
from app.rag.retrieval import retrieve
from app.config import get_settings
import json

settings = get_settings()


def killchain_agent(state: SOCState) -> SOCState:
    """
    Agent Kill Chain : reconstruit la timeline chronologique de l'attaque.
    """

    print("[KillChain] Reconstructing attack timeline...")

    techniques_str = "\n".join([
        f"- {t.get('id')} {t.get('name')} ({t.get('tactic')})"
        for t in state.get("mitre_techniques", [])
    ])

    prompt = f"""You are a cyber threat analyst reconstructing an attack timeline.

Incident: {state.get('incident_type')}
Severity: {state.get('severity')}/10

=== LOG ===
{state['raw_log']}

=== IDENTIFIED TECHNIQUES ===
{techniques_str}

Reconstruct the chronological kill chain of this attack.
Respond ONLY with valid JSON:
{{
    "kill_chain": [
        {{
            "step": 1,
            "timestamp": "extracted or estimated timestamp",
            "phase": "ATT&CK tactic name",
            "technique_id": "T1566.001",
            "description": "What the attacker did at this step",
            "severity": "high | medium | low"
        }}
    ],
    "narrative": "A paragraph describing the full attack story chronologically"
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
        print(f"[KillChain] JSON parse error: {e}")
        result = {"kill_chain": [], "narrative": ""}

    steps = result.get("kill_chain", [])
    print(f"[KillChain] → {len(steps)} steps reconstructed")

    return {
        **state,
        "kill_chain": steps,
        "kill_chain_narrative": result.get("narrative", ""),
    }