import re
from typing import Dict, Any, Tuple, List

# --- REGEX PATTERNS ---
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
SECRET_TOKEN_REGEX = re.compile(r'(?i)(b_secret_|api_key|password|passwd|secret|token|auth_key)["\s]*[:=]["\s]*([a-zA-Z0-9_\-]{16,})')
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Détection spécifique au secteur Assurance : Numéros de contrat (ex: CTR-8873211-B)
INSURANCE_POLICY_REGEX = re.compile(r'\b(?:POL|CTR|CONTRAT)[- ]\d{6,12}[- ]?[A-Z0-9]?\b', re.IGNORECASE)

class DataSanitizer:
    @staticmethod
    def extract_and_sanitize(raw_log: str) -> Tuple[str, List[Dict[str, str]]]:
        """
        1. Extrait les vrais IOCs et entités (IPs, Emails, Contrats) pour l'usage interne du SOC.
        2. Masque l'ensemble des PII et données sensibles (Cartes, Mots de passe, e-mails, Contrats d'assurance) dans le log.
        """
        extracted_iocs = []

        # 1. Extraction des IPs (visibles pour le LLM)
        ips = list(set(IP_REGEX.findall(raw_log)))
        for ip in ips:
            if not ip.startswith("127."):
                extracted_iocs.append({"type": "ip", "value": ip})

        # 2. Extraction des e-mails (avant masquage)
        emails = list(set(EMAIL_REGEX.findall(raw_log)))
        for email in emails:
            extracted_iocs.append({"type": "email", "value": email})

        # 3. Extraction des numéros de contrats d'assurance (avant masquage)
        policies = list(set(INSURANCE_POLICY_REGEX.findall(raw_log)))
        for policy in policies:
            extracted_iocs.append({"type": "insurance_policy", "value": policy})

        # 4. Processus de masquage strict pour le LLM (Groq)
        sanitized = raw_log
        sanitized = CREDIT_CARD_REGEX.sub("[REDACTED_CREDIT_CARD]", sanitized)
        sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", sanitized)
        sanitized = INSURANCE_POLICY_REGEX.sub("[REDACTED_INSURANCE_POLICY]", sanitized)

        def mask_secret(match):
            return f"{match.group(1)}: [REDACTED_SECRET]"
        sanitized = SECRET_TOKEN_REGEX.sub(mask_secret, sanitized)

        return sanitized, extracted_iocs