import re
from typing import Dict, Any, Tuple, List
from app.config import ORG_DOMAINS, is_org_domain
import ipaddress

# --- REGEX PATTERNS ---
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
SECRET_TOKEN_REGEX = re.compile(r'(?i)(b_secret_|api_key|password|passwd|secret|token|auth_key)["\s]*[:=]["\s]*([a-zA-Z0-9_\-]{16,})')
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
INSURANCE_POLICY_REGEX = re.compile(r'\b(?:POL|CTR|CONTRAT)[- ]\d{6,12}[- ]?[A-Z0-9]?\b', re.IGNORECASE)

# Domaines : deux passes distinctes (voir extract_domains)
URL_REGEX = re.compile(r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[/\s]|$)')
BARE_DOMAIN_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)
COMMON_FILE_EXTENSIONS = {
    "php", "html", "htm", "js", "css", "asp", "aspx", "jsp", "py",
    "exe", "txt", "json", "xml", "log", "dll", "sh", "bat", "zip",
    "csv", "pdf", "doc", "docx", "png", "jpg", "jpeg", "gif", "ps1"
}



def extract_domains(raw_log: str) -> set:
    """Extrait les domaines en évitant les faux positifs (chemins de fichiers, extensions)."""
    domains = set()
    text_without_urls = raw_log

    # 1. Domaines depuis les URLs explicites — le plus fiable
    for match in re.finditer(r'https?://[^\s]+', raw_log):
        url_match = URL_REGEX.match(match.group(0)) or URL_REGEX.search(match.group(0))
        if url_match:
            domains.add(url_match.group(1).lower())
        text_without_urls = text_without_urls.replace(match.group(0), " ")

    # 2. Domaines "nus" — uniquement sur le texte restant, hors URLs déjà traitées
    for match in BARE_DOMAIN_REGEX.finditer(text_without_urls):
        candidate = match.group(0).lower()
        if IP_REGEX.fullmatch(candidate):
            continue
        tld = candidate.rsplit(".", 1)[-1]
        if tld in COMMON_FILE_EXTENSIONS:
            continue
        domains.add(candidate)

    return domains

class DataSanitizer:
    @staticmethod
    def extract_and_sanitize(raw_log: str) -> Tuple[str, List[Dict[str, str]]]:
        extracted_iocs = []

        # 1. IPs
        ips = list(set(IP_REGEX.findall(raw_log)))
        for ip in ips:
            try:
                if not ipaddress.ip_address(ip).is_private:
                    extracted_iocs.append({"type": "ip", "value": ip})
            except ValueError:
                continue

        # 2. E-mails (avant masquage)
        emails = list(set(EMAIL_REGEX.findall(raw_log)))
        for email in emails:
            domain_part = email.split("@")[-1].lower()
            extracted_iocs.append({
                "type": "email",
                "value": email,
                "is_organization_asset": is_org_domain(domain_part)
            })

        # 3. Domaines (avant masquage)
        for domain in extract_domains(raw_log):
            extracted_iocs.append({
                "type": "domain",
                "value": domain,
                "is_organization_asset": is_org_domain(domain)
            })

        # 4. Numéros de contrats d'assurance (avant masquage)
        policies = list(set(INSURANCE_POLICY_REGEX.findall(raw_log)))
        for policy in policies:
            extracted_iocs.append({"type": "insurance_policy", "value": policy})

        # 5. Masquage strict pour le LLM (Groq)
        sanitized = raw_log
        sanitized = CREDIT_CARD_REGEX.sub("[REDACTED_CREDIT_CARD]", sanitized)
        sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", sanitized)
        sanitized = INSURANCE_POLICY_REGEX.sub("[REDACTED_INSURANCE_POLICY]", sanitized)

        def mask_secret(match):
            return f"{match.group(1)}: [REDACTED_SECRET]"
        sanitized = SECRET_TOKEN_REGEX.sub(mask_secret, sanitized)

        return sanitized, extracted_iocs