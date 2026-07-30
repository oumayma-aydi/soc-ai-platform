"""
Bibliothèque de catégories de preuves utilisées par le scoring pour
pondérer la qualité des preuves textuelles, sans dépendre de l'auto-
évaluation du LLM. Enrichir ce fichier n'impacte jamais scoring.py.
"""

EVIDENCE_CATEGORIES = {
    "process_execution": {
        "weight": 3,
        "patterns": [
            r'\.exe\b', r'\.dll\b', r'\.ps1\b', r'\.sh\b', r'\.bat\b',
            r'process (started|spawned|executed)',
            r'wmic', r'rundll32', r'mshta', r'regsvr32',
            r'certutil', r'schtasks', r'bitsadmin', r'powershell',
        ],
    },
    "credential_access": {
        "weight": 3,
        "patterns": [
            r'\bwhoami\b', r'net user', r'nltest', r'dsquery', r'quser', r'klist',
            r'mimikatz', r'lsass', r'\bsam\b', r'sekurlsa',
            r'failed password', r'accepted password', r'login (successful|failed)',
        ],
    },
    "file_integrity": {
        "weight": 3,
        "patterns": [
            r'vssadmin', r'mass file rename', r'files? modified',
            r'ransom note', r'\.locked', r'shadow cop',
        ],
    },
    "network_indicator": {
        "weight": 2,
        "patterns": [
            r'\b\d{1,3}(\.\d{1,3}){3}\b',
            r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            r'CVE-\d{4}-\d+', r'\bT\d{4}\b',
            r'outbound connection', r'beacon',
        ],
    },
    "generic_log": {
        "weight": 1,
        "patterns": [r'.*'],
    },
}

# Table d'alignement catégorie ↔ tactique, utilisée pour vérifier qu'une
# preuve corrobore plausiblement la tactique de la technique qu'elle appuie.
CATEGORY_TACTIC_ALIGNMENT = {
    "process_execution": {"Execution", "Defense Evasion", "Persistence"},
    "credential_access": {"Credential Access", "Discovery"},
    "file_integrity": {"Impact", "Defense Evasion"},
    "network_indicator": {"Command and Control", "Exfiltration", "Initial Access"},
}