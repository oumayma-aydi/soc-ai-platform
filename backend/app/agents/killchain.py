from langchain_groq import ChatGroq
from app.agents.state import SOCState
from app.rag.retrieval import retrieve
from app.config import get_settings
import json

settings = get_settings()


def killchain_agent(state: SOCState) -> SOCState:
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

=== CRITICAL CONSTRAINT ===
You MUST only use technique_id values that appear in the "IDENTIFIED TECHNIQUES"
list above. Do NOT invent, guess, or introduce any technique_id that is not
already in that list, even if it seems superficially related. If a log event
doesn't clearly map to any of the identified techniques, use the closest one
from the list, or omit the technique_id field rather than inventing a new one.

=== CANONICAL KILL CHAIN ORDER (SANITY GUIDE, NOT A HARD OVERRIDE) ===
Reconnaissance → Resource Development → Initial Access → Execution → Persistence →
Privilege Escalation → Defense Evasion → Credential Access → Discovery →
Lateral Movement → Collection → Command and Control → Exfiltration → Impact

Use this order as a guide when the log is ambiguous. However, if the actual
timestamps in the log contradict this canonical order (e.g. a brute-force
Credential Access attempt logged before the resulting successful Initial Access),
ALWAYS trust the real timestamps and chronology of the log over the canonical
order. The canonical order helps you sanity-check unclear cases; it must never
override what actually happened according to the evidence.

=== STRUCTURING RULES (MUST FOLLOW) ===
1. Group multiple log lines into a SINGLE kill chain step ONLY if they represent
   the EXACT SAME tactic/phase. Time proximity between log lines is NEVER a
   reason to merge them if their tactics differ — even if two events happen
   1 second apart, if one is Execution and the next is Impact, they MUST be
   two separate steps. Phase similarity is the only valid merge criterion,
   never timestamp closeness.
2. Only create a NEW step when the attacker's tactic changes, evidenced by a
   different technique or objective — not just a new timestamp.
3. Merge two steps ONLY if they are DIRECTLY ADJACENT in the sequence AND share
   the exact same phase AND the exact same technique_id. If two adjacent events
   have different techniques, even within the same broad tactic, keep them as
   separate steps.
4. A phase CAN legitimately reappear later in the kill chain if the attacker
   returns to it after doing something else in between (e.g. Credential Access
   → Discovery → Privilege Escalation → Credential Access again is CORRECT and
   must produce four separate steps, not three).
5. If the log only shows evidence for a single tactic throughout, it is correct
   to return only ONE step — never invent additional phases without evidence.
6. Each step's "phase" field and "technique_id" field must always be mutually
   consistent (the technique_id must genuinely belong to the stated phase's
   tactic). Never let a step display a phase name that doesn't match its own
   technique_id.

Reconstruct the chronological kill chain of this attack, following the rules above.

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

=== IMPORTANT — technique_id FIELD FORMAT ===
The "technique_id" field must ALWAYS be either a real MITRE ATT&CK ID from the
IDENTIFIED TECHNIQUES list (e.g. "T1003.001"), or omitted/null if uncertain.
NEVER write a hedge phrase like "Unknown from available telemetry" or
"Could not be confirmed" in this field — that kind of uncertainty belongs only
in the "description" field, never in "technique_id".

Respond ONLY with valid JSON:
{{
    "kill_chain": [
        {{
            "step": 1,
            "timestamp": "extracted or estimated timestamp",
            "phase": "ATT&CK tactic name",
            "technique_id": "T1566.001",
            "description": "What the attacker did at this step (summarize repeated events if applicable)",
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

    # 4. Parser la réponse JSON (avec réparation automatique des backslashes non échappés)
    from app.agents.json_utils import parse_llm_json
    try:
        result = parse_llm_json(raw)
    except Exception as e:
        print(f"[KillChain] JSON parse error: {e}")
        result = {"kill_chain": [], "narrative": ""}

    steps = result.get("kill_chain", [])

    # Garde-fou 1 : rejette tout technique_id qui n'a jamais été validé par
    # Mapping (y compris les phrases hedge comme "Unknown from available
    # telemetry" que le modèle pourrait injecter par erreur dans ce champ).
    valid_tech_ids = {
        (t.get("id") if isinstance(t, dict) else getattr(t, "id", None))
        for t in state.get("mitre_techniques", [])
    }
    for step in steps:
        tech_id = step.get("technique_id")
        if tech_id and tech_id not in valid_tech_ids:
            print(f"[KillChain] ⚠️ Removing ungrounded technique_id in kill chain step: {tech_id}")
            step["technique_id"] = None

    # Garde-fou 2 — Corrige toute incohérence phase/technique_id, en se
    # basant sur les techniques déjà validées par l'agent Mapping. Doit se
    # faire AVANT la déduplication, sinon deux steps qui ne semblent
    # identiques qu'après correction ne seront jamais fusionnés.
    mitre_lookup = {t.get("id"): t.get("tactic") for t in state.get("mitre_techniques", [])}
    for step in steps:
        tech_id = step.get("technique_id")
        expected_tactic = mitre_lookup.get(tech_id)
        if expected_tactic and step.get("phase") != expected_tactic:
            step["phase"] = expected_tactic

    # Dédoublonnage, sur des phases et technique_id désormais fiabilisés
    deduped_steps = []
    for step in steps:
        if deduped_steps and deduped_steps[-1].get("phase") == step.get("phase"):
            prev_desc = deduped_steps[-1].get("description", "")
            new_desc = step.get("description", "")
            deduped_steps[-1]["description"] = f"{prev_desc} {new_desc}".strip()
            deduped_steps[-1]["timestamp"] = step.get("timestamp", deduped_steps[-1].get("timestamp"))
        else:
            deduped_steps.append(step)

    for i, step in enumerate(deduped_steps, start=1):
        step["step"] = i

    print(f"[KillChain] → {len(deduped_steps)} steps reconstructed (raw: {len(steps)})")

    return {
        **state,
        "kill_chain": deduped_steps,
        "kill_chain_narrative": result.get("narrative", ""),
    }