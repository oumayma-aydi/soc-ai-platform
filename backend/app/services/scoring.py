from typing import Dict, Any

class ScoringService:
    @staticmethod
    def calculate_confidence(state: dict) -> float:
        """
        Calcule un score de confiance global déterministe (0.0 à 1.0)
        basé sur les preuves récoltées par l'ensemble des modules.
        """
        score = 0.0
        weights = {
            "triage_evidence": 0.3,  # Importance des preuves textuelles
            "ioc_malicious": 0.4,    # Importance de la réputation des IOCs (OSINT)
            "mitre_confidence": 0.3  # Importance de la clarté du mapping ATT&CK
        }

        # 1. Évaluation du Triage (Preuves extraites)
        evidence_count = len(state.get("triage_evidence", [])) if state.get("triage_evidence") else 0
        if evidence_count >= 3:
            score += weights["triage_evidence"]
        elif evidence_count > 0:
            score += weights["triage_evidence"] * 0.5

        # 2. Évaluation des IOCs (VirusTotal / AbuseIPDB)
        enrichment_data = state.get("enrichment", {})
        if enrichment_data:
            max_malicious_detected = False
            for ioc, data in enrichment_data.items():
                # Score VirusTotal
                vt = data.get("virus_total", {})
                if vt.get("malicious_score", 0) > 5:
                    max_malicious_detected = True
                
                # Score AbuseIPDB
                abuse = data.get("abuse_ipdb", {})
                if abuse.get("abuse_score", 0) > 50:
                    max_malicious_detected = True
            
            if max_malicious_detected:
                score += weights["ioc_malicious"]
            else:
                score += weights["ioc_malicious"] * 0.3
        else:
            score += weights["ioc_malicious"] * 0.4

        # 3. Évaluation du Mapping MITRE ATT&CK
        techniques = state.get("mitre_techniques", [])
        if techniques:
            try:
                # Gestion si techniques est une liste de dicts ou d'objets
                total_conf = 0.0
                for t in techniques:
                    if isinstance(t, dict):
                        total_conf += float(t.get("confidence", 0.5))
                    else:
                        total_conf += float(getattr(t, "confidence", 0.5))
                avg_mitre_conf = total_conf / len(techniques)
                score += weights["mitre_confidence"] * avg_mitre_conf
            except Exception:
                score += weights["mitre_confidence"] * 0.5
        else:
            score += weights["mitre_confidence"] * 0.2

        return round(min(score, 1.0), 2)