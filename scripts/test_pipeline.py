import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.agents.pipeline import run_analysis
from app.models.incident import Incident  # On importe notre validateur Pydantic
import json

# Scénario 1 du cahier des charges — Phishing → Account Takeover
log_phishing = """
08:14 - Email received from external sender: support@micros0ft-secure.com
        Subject: "Urgent: Your account will be suspended"
        Link detected: http://185.220.101.47/login/office365

08:31 - User clicked suspicious link
        Browser redirect: http://185.220.101.47/login/office365
        Page title: "Microsoft Office 365 - Sign In"

08:47 - Authentication alert: credentials submitted to unknown IP
        Source IP: 185.220.101.47
        Country: Romania
        User: jean.dupont@star-assurance.tn

08:53 - VPN connection established from Bulgaria (BG)
        User: jean.dupont@star-assurance.tn
        IP: 185.220.101.47
        Country not declared in user profile

09:02 - Mass file access detected
        User: jean.dupont@star-assurance.tn
        Files: /sinistres/clients/*.pdf (47 files accessed in 3 minutes)
        Location: Claims department shared drive
"""

print("=" * 60)
print("SOC AI Platform — Pipeline Test")
print("Scenario: Phishing → Account Takeover")
print("=" * 60)

# === ÉTAPE 1 : VALIDATION DES ENTRÉES AVEC PYDANTIC ===
print("[Test] Validating log input through Pydantic guardrail...")
try:
    # Pydantic vérifie la longueur et bloque les injections de prompt
    validated_input = Incident(raw_log=log_phishing, id="INC-2026-001")
    print("✅ Input successfully validated by Pydantic.")
except Exception as e:
    print(f"❌ Input Validation Error: {e}")
    sys.exit(1)

# === ÉTAPE 2 : PRÉPARATION DE L'ENRICHISSEMENT IOC (Threat Intel) ===
# On simule les données que ton module asynchrone (VirusTotal/AbuseIPDB) récolte
mock_enrichment = {
    "185.220.101.47": {
        "virus_total": {
            "malicious_score": 18,
            "harmless_score": 40
        },
        "abuse_ipdb": {
            "abuse_score": 100,
            "country": "RO",
            "isp": "Suspicious Hosting Provider"
        }
    }
}

# === ÉTAPE 3 : EXECUTION DU PIPELINE AVEC ENRICHISSEMENT ===
# On passe le log validé ET le dictionnaire d'enrichissement
result = run_analysis(
    raw_log=validated_input.raw_log, 
    incident_id=validated_input.id, 
    enrichment=mock_enrichment
)

print("\n" + "=" * 60)
print("FINAL REPORT")
print("=" * 60)
print(f"Incident Type    : {result['incident_type']}")
print(f"Severity         : {result['severity']}/10")
print(f"Urgency          : {result['urgency']}")
# ON AFFICHE LE SCORE DE CONFIANCE REÇU DU PIPELINE
print(f"Confidence Score : {result.get('confidence_score', 0.0)}/1.0 🎯")

print(f"\nATT&CK Techniques ({len(result['mitre_techniques'])}):")
for t in result['mitre_techniques']:
    print(f"  {t.get('id')} - {t.get('name')} (confidence: {t.get('confidence')})")

print(f"\nKill Chain ({len(result['kill_chain'])} steps):")
for step in result['kill_chain']:
    print(f"  Step {step.get('step')} [{step.get('phase')}] {step.get('description','')[:60]}")

print(f"\nRemediation Actions:")
for action in result.get('remediation', {}).get('actions', []):
    print(f"  P{action.get('priority')} [{action.get('timeframe')}]")
    print(f"    → {action.get('action')}")
    print(f"    How: {action.get('how','')[:80]}")
    print(f"    Source: {action.get('source')}")

print(f"\nDetections to deploy:")
for d in result.get('remediation', {}).get('detections_to_deploy', []):
    print(f"  • {d}")

print(f"\nSummary: {result.get('remediation', {}).get('summary', '')[:200]}")