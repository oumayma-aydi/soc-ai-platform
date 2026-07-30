import math
import re
from typing import Dict, Any

from app.services.evidence_patterns import EVIDENCE_CATEGORIES, CATEGORY_TACTIC_ALIGNMENT


def _matched_categories(evidence_text: str) -> list:
    """
    Retourne TOUTES les catégories dont un pattern matche le texte,
    pas seulement la première trouvée — une preuve peut légitimement
    appartenir à plusieurs catégories (ex: "powershell to 1.2.3.4"
    est à la fois process_execution ET network_indicator).
    """
    text = evidence_text.lower()
    matched = []
    for category, config in EVIDENCE_CATEGORIES.items():
        if category == "generic_log":
            continue
        if any(re.search(p, text) for p in config["patterns"]):
            matched.append(category)
    return matched


def _evidence_weight(evidence_text: str) -> float:
    """Poids d'une preuve = le MAX parmi toutes les catégories matchées,
    jamais dépendant de l'ordre du dictionnaire."""
    matched = _matched_categories(evidence_text)
    if not matched:
        return EVIDENCE_CATEGORIES["generic_log"]["weight"]
    return max(EVIDENCE_CATEGORIES[c]["weight"] for c in matched)


def _evidence_supports_tactic(evidence_text: str, tactic: str) -> bool:
    """Vérifie si une preuve appartient à au moins une catégorie
    plausiblement alignée avec la tactique donnée."""
    matched = _matched_categories(evidence_text)
    for category in matched:
        if tactic in CATEGORY_TACTIC_ALIGNMENT.get(category, set()):
            return True
    return False


# Tactiques plausibles par type d'incident (Triage ↔ Mapping consistency)
PLAUSIBLE_TACTICS_BY_TYPE = {
    "Ransomware Attack": {"Execution", "Impact", "Defense Evasion"},
    "Phishing": {"Initial Access", "Persistence"},
    "SQL Injection": {"Initial Access", "Collection", "Discovery"},
    "Brute Force": {"Credential Access", "Initial Access"},
    "Data Exfiltration": {"Exfiltration", "Collection", "Discovery"},
    "DDoS": {"Impact"},
}


class ScoringService:
    @staticmethod
    def calculate_confidence(state: dict) -> float:
        """
        Calcule un score de confiance déterministe (0.0 à 1.0).

        Principe directeur : ne jamais pénaliser une absence de preuve
        (on ne sait pas toujours tout observer) — pénaliser uniquement
        une contradiction (technique affirmée sans preuve alignée,
        désaccord factuel entre agents).

        Répartition :
          35% — Qualité des preuves (pondérée par catégorie, jamais comptées)
          25% — Corroboration OSINT (ratio réel, pas de seuil arbitraire)
          20% — Cohérence MITRE (preuve alignée avec la tactique affirmée)
          10% — Cohérence inter-agents (Triage / Mapping / Kill Chain)
          -10% max — Pénalités (contradictions factuelles uniquement)
        """

        # ── 1. Qualité des preuves (35%) ──────────────────────────────
        evidence_list = state.get("triage_evidence", []) or []
        if evidence_list:
            total_weight = sum(_evidence_weight(str(e)) for e in evidence_list)
            evidence_score = min(total_weight / 12, 1.0)
        else:
            evidence_score = 0.0

        # ── 2. Corroboration OSINT (25%) ──────────────────────────────
        enrichment_data = state.get("enrichment", {}) or {}
        extracted_iocs = state.get("iocs", []) or []

        if not extracted_iocs:
            osint_score = 0.5  # aucun IOC attendu — neutre
        elif not enrichment_data:
            osint_score = 0.2  # IOC présents mais enrichissement indisponible
        else:
            osint_ratios = []
            for ioc, data in enrichment_data.items():
                if not isinstance(data, dict):
                    continue
                vt = data.get("virus_total", {}) or {}
                abuse = data.get("abuse_ipdb", {}) or {}
                otx = data.get("alienvault_otx", {}) or {}

                malicious = vt.get("malicious_score", 0)
                harmless = vt.get("harmless_score", 0)
                total_vt = malicious + harmless
                vt_ratio = (malicious / total_vt) if total_vt > 0 else None

                abuse_score = abuse.get("abuse_score")
                abuse_ratio = (abuse_score / 100) if abuse_score is not None else None

                pulse_count = otx.get("pulse_count", 0)
                otx_ratio = min(math.log(pulse_count + 1, 10), 1.0) if pulse_count else None

                valid = [r for r in [vt_ratio, abuse_ratio, otx_ratio] if r is not None]
                if valid:
                    osint_ratios.append(sum(valid) / len(valid))

            osint_score = sum(osint_ratios) / len(osint_ratios) if osint_ratios else 0.3

        # ── 3. Cohérence MITRE (20%) — preuve alignée avec la tactique ──
        techniques = state.get("mitre_techniques", []) or []
        if techniques:
            supported = 0
            for t in techniques:
                evidence_items = t.get("evidence") if isinstance(t, dict) else getattr(t, "evidence", None)
                tactic = t.get("tactic") if isinstance(t, dict) else getattr(t, "tactic", None)
                if evidence_items and tactic:
                    if any(_evidence_supports_tactic(str(e), tactic) for e in evidence_items):
                        supported += 1
            mitre_score = supported / len(techniques)
        else:
            mitre_score = 0.0

        # ── 4. Cohérence inter-agents (10%) ───────────────────────────
        consistency_checks = []

        mitre_tactics = {
            (t.get("tactic") if isinstance(t, dict) else getattr(t, "tactic", None))
            for t in techniques
        }
        kill_chain = state.get("kill_chain", []) or []

        # a) Chaque phase du kill chain correspond à une tactique validée par Mapping
        if kill_chain:
            aligned = sum(1 for step in kill_chain if step.get("phase") in mitre_tactics)
            consistency_checks.append(aligned / len(kill_chain))

        # b) Le kill chain ne doit pas être vide si des techniques ont été identifiées
        if techniques:
            consistency_checks.append(1.0 if kill_chain else 0.3)

        # c) Une sévérité élevée doit être appuyée par une tactique à fort impact
        severity = state.get("severity", 5) or 5
        if severity >= 7:
            high_impact_tactics = {"Impact", "Exfiltration", "Credential Access"}
            consistency_checks.append(1.0 if (mitre_tactics & high_impact_tactics) else 0.4)

        # d) Le type d'incident (Triage) est cohérent avec au moins une tactique plausible
        incident_type = state.get("incident_type", "")
        expected_tactics = PLAUSIBLE_TACTICS_BY_TYPE.get(incident_type)
        if expected_tactics and mitre_tactics:
            consistency_checks.append(1.0 if (mitre_tactics & expected_tactics) else 0.3)

        consistency_score = (
            sum(consistency_checks) / len(consistency_checks)
            if consistency_checks else 0.7
        )

        # ── 5. Pénalités (contradictions uniquement) ──────────────────
        penalty = 0.0

        unsupported_techniques = 0
        for t in techniques:
            evidence_items = t.get("evidence") if isinstance(t, dict) else getattr(t, "evidence", None)
            tactic = t.get("tactic") if isinstance(t, dict) else getattr(t, "tactic", None)
            supports = False
            if evidence_items and tactic:
                supports = any(_evidence_supports_tactic(str(e), tactic) for e in evidence_items)
            if not supports:
                unsupported_techniques += 1
        if techniques:
            penalty += min((unsupported_techniques / len(techniques)) * 0.06, 0.06)

        valid_tech_ids = {
            (t.get("id") if isinstance(t, dict) else getattr(t, "id", None))
            for t in techniques
        }
        if kill_chain:
            orphan_steps = sum(
                1 for step in kill_chain
                if step.get("technique_id") and step.get("technique_id") not in valid_tech_ids
            )
            penalty += min((orphan_steps / len(kill_chain)) * 0.04, 0.04)

        penalty = min(penalty, 0.10)

        # ── Score final ────────────────────────────────────────────────
        raw_score = (
            evidence_score * 0.35
            + osint_score * 0.25
            + mitre_score * 0.20
            + consistency_score * 0.10
        ) - penalty

        print("========== SCORE DEBUG ==========")
        print("Evidence:", evidence_score)
        print("OSINT:", osint_score)
        print("MITRE:", mitre_score)
        print("Consistency:", consistency_score)
        print("Penalty:", penalty)
        print("RAW:", raw_score)
        final = round(max(min(raw_score, 1.0), 0.0), 2)
        print("FINAL:", final)
        print("=================================")

        return round(max(min(raw_score, 1.0), 0.0), 2)