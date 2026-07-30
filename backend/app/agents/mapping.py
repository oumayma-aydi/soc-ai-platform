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

    # 1. RAG — top_k augmenté pour une meilleure couverture de contexte
    query = f"{state.get('incident_type', '')} {state['raw_log'][:150]}"
    rag_results = retrieve(query, top_k=10)

    attack_chunks = [r for r in rag_results if r['metadata'].get('source') == 'attack']

    rag_context = "\n".join([
        f"- [{r['metadata'].get('technique','')}] "
        f"{r['metadata'].get('title', '')}: {r['content'][:300]}"
        for r in attack_chunks
    ])

    prompt = f"""You are a MITRE ATT&CK expert analyst.

Incident Type: {state.get('incident_type')}
Severity: {state.get('severity')}/10

=== LOG ===
{state['raw_log']}

=== RELEVANT ATT&CK TECHNIQUES (retrieved from knowledge base) ===
{rag_context}

=== OBSERVED EVIDENCE ===
{json.dumps(state.get('triage_evidence', []))}

=== CRITICAL CONSTRAINT — GROUNDING ===
Only use technique IDs that are real, existing MITRE ATT&CK technique IDs.
STRONGLY prefer IDs that appear in the "RELEVANT ATT&CK TECHNIQUES" context above,
since those are verified against the actual MITRE database and directly retrieved
for this incident. If you propose a technique_id that does NOT appear in that
context, you MUST be able to justify it with a very specific, unambiguous match
to the log evidence — do not propose a technique just because it seems thematically
related. When uncertain between two similar techniques, prefer the one explicitly
listed in the context above. Do not invent atmospheric or loosely-related
techniques (e.g. do not map a simple file rename to a rare defense-evasion
sub-technique unless the log shows the actual mechanism, not just the outcome).

=== SUB-TECHNIQUE PRECISION ===
When the evidence supports it, use the most specific sub-technique ID available
(e.g. T1110.001 "Password Guessing" rather than the generic T1110 "Brute Force")
rather than staying at the parent technique level. Only use the parent technique
ID if the evidence is not specific enough to determine which sub-technique applies.

=== EVIDENCE CERTAINTY LANGUAGE (MUST FOLLOW) ===
Distinguish clearly between what is directly evidenced in the log versus what is
inferred or assumed. Use precise hedging language:
- "Confirmed" / definitive verbs (executed, detected, established) — ONLY when
  the log directly and unambiguously shows this happened.
- "Likely" / "Evidence suggests" / "Possibly" — when reasonably inferred but not
  directly observed.
- "Could not be confirmed" / "Unknown from available telemetry" — for any
  standard attack element the log does NOT provide direct evidence for.
Never state something as fact if it is actually an assumption.

Map this incident to MITRE ATT&CK techniques. For each technique, provide a
short plain-language explanation of how the technique generally works (not
specific to this incident — a general definition), and a concrete detection
recommendation specific to that technique (not a generic remediation action).

Respond ONLY with valid JSON:
{{
    "techniques": [
        {{
            "id": "T1566.001",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "confidence": 0.92,
            "evidence": ["specific log line or observation that proves this technique"],
            "description": "One or two sentences explaining how this technique generally
                works, independent of this specific incident.",
            "detection_recommendation": "A specific, actionable detection method for
                this exact technique (e.g. a SIEM query pattern, an EDR rule concept,
                or a log source to monitor) — not a generic remediation action."
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

    from app.agents.json_utils import parse_llm_json
    try:
        result = parse_llm_json(raw)
    except Exception as e:
        print(f"[Mapping] JSON parse error: {e}")
        result = {"techniques": []}

    from app.rag.mitre_whitelist import get_valid_mitre_ids

    techniques = result.get("techniques", [])
    valid_ids = get_valid_mitre_ids()

    # Ids présents dans le contexte RAG retrieval — sert à distinguer les
    # techniques bien ancrées de celles proposées "hors contexte" par le LLM
    rag_technique_ids = {r['metadata'].get('technique') for r in attack_chunks if r['metadata'].get('technique')}

    validated_techniques = []
    for t in techniques:
        tech_id = t.get("id")
        if tech_id not in valid_ids:
            print(f"[Mapping] ⚠️ Rejected hallucinated technique_id: {tech_id} ({t.get('name')})")
            continue
        if tech_id not in rag_technique_ids:
            print(f"[Mapping] ℹ️ Technique {tech_id} accepted but not grounded in RAG context — flagged as lower confidence")
            t["rag_grounded"] = False
        else:
            t["rag_grounded"] = True
        validated_techniques.append(t)

    print(f"[Mapping] → {len(validated_techniques)} valid techniques identified "
          f"({len(techniques) - len(validated_techniques)} rejected as hallucinated)")
    for t in validated_techniques:
        grounding = "✓ grounded" if t.get("rag_grounded") else "⚠ ungrounded"
        print(f"  {t.get('id')} - {t.get('name')} ({grounding}, confidence: {t.get('confidence')})")

    return {
        **state,
        "mitre_techniques": validated_techniques,
    }