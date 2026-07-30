from langchain_groq import ChatGroq
from app.agents.state import SOCState
from app.rag.retrieval import retrieve
from app.config import get_settings
from app.agents.json_utils import parse_llm_json
import json
from app.config import ORG_DOMAINS

settings = get_settings()


def remediation_agent(state: SOCState) -> SOCState:
    print("######## REMEDIATION VERSION 2026 ########")
    """
    Agent Remediation : génère un plan de réponse à incident opérationnel,
    structuré selon les phases NIST SP 800-61 (Containment/Eradication/
    Recovery/Detection). Basé sur D3FEND + CISA + OWASP via RAG.
    """

    print("[Remediation] Generating structured recommendations...")

    query = (
        f"remediation "
        f"{state.get('incident_type')} "
        f"{' '.join([t.get('id','') for t in state.get('mitre_techniques',[])])}"
    )

    rag_results = retrieve(query, top_k=8)

    d3fend_chunks = [r for r in rag_results if r["metadata"].get("source") == "d3fend"]
    cisa_chunks = [r for r in rag_results if r["metadata"].get("source") == "cisa"]
    owasp_chunks = [r for r in rag_results if r["metadata"].get("source") == "owasp"]

    # Sources RAG réellement consultées — extraites par le code, pas
    # auto-déclarées par le LLM. Transparence garantie sur ce qui a
    # concrètement nourri la génération, indépendamment de ce que le
    # modèle affirme avoir utilisé.
    retrieved_sources = (
        [{"framework": "D3FEND", "title": r["metadata"].get("title", ""), "relevance": round(1 - r.get("distance", 0), 2)} for r in d3fend_chunks]
        + [{"framework": "CISA KEV", "title": r["metadata"].get("technique", ""), "relevance": round(1 - r.get("distance", 0), 2)} for r in cisa_chunks]
        + [{"framework": "OWASP", "title": r["metadata"].get("title", ""), "relevance": round(1 - r.get("distance", 0), 2)} for r in owasp_chunks]
    )

    rag_context = ""
    if d3fend_chunks:
        rag_context += "=== D3FEND ===\n"
        rag_context += "\n".join(f"- {r['metadata'].get('title','')}: {r['content'][:250]}" for r in d3fend_chunks)
    if cisa_chunks:
        rag_context += "\n=== CISA ===\n"
        rag_context += "\n".join(f"- {r['metadata'].get('technique','')}: {r['content'][:250]}" for r in cisa_chunks)
    if owasp_chunks:
        rag_context += "\n=== OWASP ===\n"
        rag_context += "\n".join(f"- {r['metadata'].get('title','')}: {r['content'][:250]}" for r in owasp_chunks)

    techniques = ", ".join(f"{t.get('id')} {t.get('name')}" for t in state.get("mitre_techniques", []))

    # Schéma de sortie construit en dict Python puis sérialisé — élimine
    # tout risque d'accolade non échappée dans le f-string du prompt.
        # Schéma de sortie construit en dict Python puis sérialisé.
    # IMPORTANT : ici on construit un vrai dictionnaire Python,
    # donc on utilise uniquement { } et jamais {{ }}.
    output_schema_example = {
        "actions": [
            {
                "phase": "Containment",
                "priority": 1,
                "necessity": "Mandatory",
                "confidence": "High",
                "timeframe": "<15 min",
                "action": "",
                "evidence": "",
                "procedure": {
                    "why": "",
                    "steps": [
                        "",
                        "",
                        ""
                    ],
                    "commands": [
                        {
                            "title": "Windows Firewall",
                            "command": ""
                        },
                        {
                            "title": "PowerShell",
                            "command": ""
                        },
                        {
                            "title": "EDR",
                            "command": ""
                        }
                    ]
                },
                "business_impact": "",
                "source": {
                    "framework": "",
                    "id": "",
                    "title": ""
                }
            }
        ],
        "detections_to_deploy": [
            {
                "title": "",
                "objective": "",
                "severity": "High",
                "sigma": {
                    "title": "",
                    "rule": ""
                },
                "splunk": {
                    "title": "",
                    "query": ""
                },
                "kql": {
                    "title": "",
                    "query": ""
                }
            }
        ],
        "summary": {
            "confirmed": [],
            "likely": [],
            "not_confirmed": [],
            "overall_assessment": ""
        }
    }

    output_schema_json = json.dumps(output_schema_example, indent=2)

    prompt = f"""
You are a Senior Incident Response Lead and SOC Level-3 Analyst working for a large insurance company.

Your job is NOT to summarize the incident.
Your job is to produce an operational Incident Response plan following NIST SP 800-61.
The response must be extremely practical and written as if another SOC analyst will execute it immediately.


=== ORGANIZATION CONTEXT (CRITICAL — READ FIRST) ===
This incident concerns STAR Assurances, a Tunisian insurance company.
The organization's own domain(s): {", ".join(ORG_DOMAINS)}
Any username, email address, or domain matching {", ".join(ORG_DOMAINS)} belongs to
the VICTIM ORGANIZATION and its employees — NOT to an attacker.
STAR Assurances is the TARGET of this incident, never the source.

RULE: NEVER recommend blocking, blacklisting, sinkholing, or firewalling
{", ".join(ORG_DOMAINS)} or any subdomain/account under it. This is internal
infrastructure. Blocking it would be a self-inflicted outage, not a remediation.

If IOC domains or emails match the organization's own domain, treat the associated
USERNAMES as compromised or targeted ACCOUNTS requiring account-level remediation
(password reset, MFA enforcement, session/token revocation, conditional access,
account lockout review) — not network-level blocking.

Only external domains/IPs (confirmed via OSINT enrichment as NOT belonging to the
organization) are valid candidates for network-level blocking.

=== INCIDENT ===
Type: {state.get('incident_type')}
Severity: {state.get('severity')}/10
Urgency: {state.get('urgency')}

=== MITRE ATT&CK ===
{techniques}

=== KILL CHAIN ===
{state.get('kill_chain_narrative','')}

=== EXTRACTED IOCS ===
{json.dumps(state.get('iocs', []), indent=2)}

=== OSINT ===
{json.dumps(state.get('enrichment', {}), indent=2)[:1000]}

=== KNOWLEDGE BASE ===
{rag_context}

=== MANDATORY RULES ===
1. Every remediation MUST explicitly reference the evidence that triggered it.
2. NEVER invent evidence.
3. Distinguish clearly between: Confirmed by logs / Likely / Cannot be confirmed.
4. Organize recommendations according to Incident Response phases: Containment, Eradication, Recovery, Detection Improvements.
5. Every action MUST contain: phase, priority, necessity, confidence, action, evidence, business impact, detailed procedure, concrete commands, D3FEND/CISA/OWASP reference.
6. Procedures MUST be operational. Instead of "Block the IP", give realistic examples: firewall ACL, Windows Firewall, iptables, Palo Alto, Defender isolation, PowerShell, Sigma rule, Splunk SPL, Microsoft Sentinel KQL. Commands don't need to be executable as-is but must be realistic.
7. If the incident is phishing or email-based AND the malicious domain is EXTERNAL
   (not the organization's own domain), ALWAYS prioritize blocking that external
   domain, never the IP as primary action. If the only domain involved is the
   organization's own domain, this rule does NOT apply — see ORGANIZATION CONTEXT rule above.
7b. For brute force / credential access / account takeover incidents targeting
   organization accounts, prioritize: forced password reset, MFA enrollment/enforcement,
   session revocation, conditional access policy tightening, and account lockout —
   in that order — NOT domain or IP blocking of the organization's own infrastructure.
8. Mention business impact whenever containment could interrupt legitimate services.
9. If logs do not prove persistence, privilege escalation or exfiltration, explicitly say so.
10. Recommendations must be specific to THIS incident — avoid generic cybersecurity advice.

=== OUTPUT ===
Respond with valid JSON matching EXACTLY this schema (same keys, filled with real values for this incident):

{output_schema_json}

Return ONLY JSON. Do not add markdown. Do not add explanations.
"""

    llm = ChatGroq(
        api_key=settings.GROQ_API_KEY,
        model="llama-3.3-70b-versatile",
        temperature=0,
    )

    response = llm.invoke(prompt)
    raw = response.content.strip()

    try:
        result = parse_llm_json(raw)
    except Exception as e:
        print(f"[Remediation] JSON parse error: {e}")
        result = {"actions": [], "detections_to_deploy": [], "summary": {"overall_assessment": raw}}

    # Injecte les sources RAG réelles dans le JSON stocké — pas besoin de
    # migration DB, ça voyage dans la même colonne "remediation" (JSON).
    result["rag_sources_consulted"] = retrieved_sources

    actions = result.get("actions", [])
    print(f"[Remediation] → {len(actions)} actions generated, {len(retrieved_sources)} RAG sources consulted")
    for action in actions:
        print(f"  {action.get('phase')} {action.get('action','')[:80]}")

    return {
        **state,
        "remediation": result,
    }