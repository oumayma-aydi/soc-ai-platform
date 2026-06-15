import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from app.sanitization.sanitizer import DataSanitizer

# Un log fictif mais critique contenant des fuites de données PII
dirty_log = """
14:22:01 - User Session Init - User: amina.benali@star-assurance.tn
14:22:15 - Payment Gateway Alert - Customer submitted credit card 4111-2222-3333-4444 for policy renewal.
14:22:30 - Debug Log Dump - Failed webhook authentication. Context: api_key="sk_live_51Nx82HjKls92KlzP000000"
14:23:12 - Support ticket created by billing@external-partner.com regarding Contract CTR-8873211-B.
14:24:00 - Outbound connection to malicious C2 server IP: 185.220.101.47
"""

def main():
    print("=" * 60)
    print("SOC AI Platform — Data Sanitization & Extraction Test")
    print("=" * 60)
    
    print("\n--- LOG ORIGINAL (AVANT TRAITEMENT) ---")
    print(dirty_log.strip())
    print("-" * 60)
    
    # Appel de la bonne méthode optimisée
    sanitized_log, extracted_iocs = DataSanitizer.extract_and_sanitize(dirty_log)
    
    print("\n--- LOG SÉCURISÉ (ENVOYÉ AU LLM) ---")
    print(sanitized_log.strip())
    print("-" * 60)
    
    print("\n--- IOCs EXTRAITS SÉCURISÉS (POUR VIRUSTOTAL / RAG) ---")
    import json
    print(json.dumps(extracted_iocs, indent=2))
    print("=" * 60)

if __name__ == "__main__":
    main()