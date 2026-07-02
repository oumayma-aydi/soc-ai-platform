import os
import asyncio
import httpx
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY")
OTX_KEY        = os.getenv("OTX_API_KEY")

TIMEOUT = 5.0


# ═══════════════════════════════════════════════════════════════════
# OSINT ENRICHMENT FUNCTIONS (unchanged)
# ═══════════════════════════════════════════════════════════════════

async def check_virus_total(client: httpx.AsyncClient, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Interroge l'API VirusTotal v3 pour une IP, un domaine ou un hash."""
    if not VIRUSTOTAL_KEY:
        return {"error": "API Key manquante"}

    endpoint_map = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {"error": f"Type d'IOC non supporté par VT: {ioc_type}"}

    headers = {"x-apikey": VIRUSTOTAL_KEY}
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc_value}"

    try:
        response = await client.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            data  = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious_score": stats.get("malicious", 0),
                "harmless_score":  stats.get("harmless", 0),
                "category":        data.get("attributes", {}).get("categories", {}),
            }
        return {"status_code": response.status_code, "error": response.text}
    except Exception as e:
        return {"error": str(e)}


async def check_abuse_ipdb(client: httpx.AsyncClient, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Interroge l'API AbuseIPDB pour les adresses IP uniquement."""
    if ioc_type != "ip":
        return {}
    if not ABUSEIPDB_KEY:
        return {"error": "API Key manquante"}

    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ioc_value, "maxAgeInDays": "90"}
    url     = "https://api.abuseipdb.com/api/v2/check"

    try:
        response = await client.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score":   data.get("abuseConfidenceScore", 0),
                "country":       data.get("countryCode"),       # ISO alpha-2 ex: "RU", "CN"
                "isp":           data.get("isp"),
                "total_reports": data.get("totalReports", 0),
            }
        return {"status_code": response.status_code, "error": response.text}
    except Exception as e:
        return {"error": str(e)}


async def check_alienvault_otx(client: httpx.AsyncClient, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Interroge l'API AlienVault OTX."""
    if not OTX_KEY:
        return {"error": "API Key manquante"}

    endpoint_map = {"ip": "IPv4", "domain": "domain", "hash": "file"}
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {"error": f"Type d'IOC non supporté par OTX: {ioc_type}"}

    headers = {"X-OTX-API-KEY": OTX_KEY}
    url     = f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/{ioc_value}/general"

    try:
        response = await client.get(url, headers=headers, timeout=30.0)
        if response.status_code == 200:
            data       = response.json()
            pulse_info = data.get("pulse_info", {})
            pulses     = pulse_info.get("pulses", [])
            tags = []
            for p in pulses:
                for tag in p.get("tags", []):
                    if tag and tag not in tags:
                        tags.append(tag)
            return {
                "pulse_count": pulse_info.get("count", 0),
                "references":  [p.get("name") for p in pulses[:3]],
                "tags":        tags[:5],
            }
        return {"status_code": response.status_code, "error": f"Erreur API OTX: {response.text[:100]}"}
    except httpx.TimeoutException:
        return {"error": "Timeout de 5s atteint pour AlienVault OTX"}
    except Exception as e:
        return {"error": f"Erreur inattendue OTX: {str(e)}"}


async def enrich_ioc(ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Lance les requêtes OSINT en parallèle grâce à asyncio.gather()."""
    async with httpx.AsyncClient() as client:
        tasks = [
            check_virus_total(client, ioc_type, ioc_value),
            check_abuse_ipdb(client, ioc_type, ioc_value),
            check_alienvault_otx(client, ioc_type, ioc_value),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {
            "ioc":             ioc_value,
            "type":            ioc_type,
            "virus_total":     results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])},
            "abuse_ipdb":      results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])},
            "alienvault_otx":  results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])},
        }


# ═══════════════════════════════════════════════════════════════════
# GEOGRAPHIC COORDINATE MAPPING
# Centroides géographiques ISO 3166-1 alpha-2 → lat/lon
# Utilisés par react-simple-maps et d3-geo côté frontend.
# ═══════════════════════════════════════════════════════════════════

COUNTRY_CENTROIDS: Dict[str, Dict[str, Any]] = {
    # ── Afrique ──────────────────────────────────────────────────────
    "DZ": {"lat": 28.03,  "lon":  1.66,   "name": "Algérie"},
    "AO": {"lat": -11.20, "lon": 17.87,   "name": "Angola"},
    "BJ": {"lat":   9.31, "lon":  2.32,   "name": "Bénin"},
    "BW": {"lat": -22.33, "lon": 24.68,   "name": "Botswana"},
    "BF": {"lat":  12.36, "lon": -1.56,   "name": "Burkina Faso"},
    "BI": {"lat":  -3.37, "lon": 29.92,   "name": "Burundi"},
    "CM": {"lat":   7.37, "lon": 12.35,   "name": "Cameroun"},
    "CF": {"lat":   6.61, "lon": 20.94,   "name": "Rép. Centrafricaine"},
    "TD": {"lat":  15.45, "lon": 18.73,   "name": "Tchad"},
    "CD": {"lat":  -4.04, "lon": 21.76,   "name": "RD Congo"},
    "CG": {"lat":  -0.23, "lon": 15.83,   "name": "Congo"},
    "CI": {"lat":   7.54, "lon": -5.55,   "name": "Côte d'Ivoire"},
    "DJ": {"lat":  11.83, "lon": 42.59,   "name": "Djibouti"},
    "EG": {"lat":  26.82, "lon": 30.80,   "name": "Égypte"},
    "GQ": {"lat":   1.65, "lon": 10.27,   "name": "Guinée Équatoriale"},
    "ER": {"lat":  15.18, "lon": 39.78,   "name": "Érythrée"},
    "ET": {"lat":   9.15, "lon": 40.49,   "name": "Éthiopie"},
    "GA": {"lat":  -0.80, "lon": 11.61,   "name": "Gabon"},
    "GM": {"lat":  13.44, "lon": -15.31,  "name": "Gambie"},
    "GH": {"lat":   7.95, "lon": -1.02,   "name": "Ghana"},
    "GN": {"lat":   9.95, "lon": -11.24,  "name": "Guinée"},
    "GW": {"lat":  11.80, "lon": -15.18,  "name": "Guinée-Bissau"},
    "KE": {"lat":  -0.02, "lon": 37.91,   "name": "Kenya"},
    "LS": {"lat": -29.61, "lon": 28.23,   "name": "Lesotho"},
    "LR": {"lat":   6.43, "lon": -9.43,   "name": "Libéria"},
    "LY": {"lat":  26.34, "lon": 17.23,   "name": "Libye"},
    "MG": {"lat": -18.77, "lon": 46.87,   "name": "Madagascar"},
    "MW": {"lat": -13.25, "lon": 34.30,   "name": "Malawi"},
    "ML": {"lat":  17.57, "lon": -3.99,   "name": "Mali"},
    "MR": {"lat":  21.01, "lon": -10.94,  "name": "Mauritanie"},
    "MA": {"lat":  31.79, "lon": -7.09,   "name": "Maroc"},
    "MZ": {"lat": -18.67, "lon": 35.53,   "name": "Mozambique"},
    "NA": {"lat": -22.96, "lon": 18.49,   "name": "Namibie"},
    "NE": {"lat":  17.61, "lon":  8.08,   "name": "Niger"},
    "NG": {"lat":   9.08, "lon":  8.68,   "name": "Nigéria"},
    "RW": {"lat":  -1.94, "lon": 29.87,   "name": "Rwanda"},
    "SN": {"lat":  14.50, "lon": -14.45,  "name": "Sénégal"},
    "SL": {"lat":   8.46, "lon": -11.78,  "name": "Sierra Leone"},
    "SO": {"lat":   5.15, "lon": 46.20,   "name": "Somalie"},
    "ZA": {"lat": -30.56, "lon": 22.94,   "name": "Afrique du Sud"},
    "SS": {"lat":   4.86, "lon": 31.57,   "name": "Soudan du Sud"},
    "SD": {"lat":  12.86, "lon": 30.22,   "name": "Soudan"},
    "TZ": {"lat":  -6.37, "lon": 34.89,   "name": "Tanzanie"},
    "TG": {"lat":   8.62, "lon":  0.82,   "name": "Togo"},
    "TN": {"lat":  33.89, "lon":  9.54,   "name": "Tunisie"},
    "UG": {"lat":   1.37, "lon": 32.29,   "name": "Ouganda"},
    "ZM": {"lat": -13.13, "lon": 27.85,   "name": "Zambie"},
    "ZW": {"lat": -19.02, "lon": 29.15,   "name": "Zimbabwe"},
    # ── Amériques ────────────────────────────────────────────────────
    "AR": {"lat": -38.42, "lon": -63.62,  "name": "Argentine"},
    "BO": {"lat": -16.29, "lon": -63.59,  "name": "Bolivie"},
    "BR": {"lat": -14.24, "lon": -51.93,  "name": "Brésil"},
    "CA": {"lat":  56.13, "lon": -106.35, "name": "Canada"},
    "CL": {"lat": -35.68, "lon": -71.54,  "name": "Chili"},
    "CO": {"lat":   4.57, "lon": -74.30,  "name": "Colombie"},
    "CR": {"lat":   9.75, "lon": -83.75,  "name": "Costa Rica"},
    "CU": {"lat":  21.52, "lon": -77.78,  "name": "Cuba"},
    "DO": {"lat":  18.74, "lon": -70.16,  "name": "Rép. Dominicaine"},
    "EC": {"lat":  -1.83, "lon": -78.18,  "name": "Équateur"},
    "SV": {"lat":  13.79, "lon": -88.90,  "name": "Salvador"},
    "GT": {"lat":  15.78, "lon": -90.23,  "name": "Guatemala"},
    "HT": {"lat":  18.97, "lon": -72.29,  "name": "Haïti"},
    "HN": {"lat":  15.20, "lon": -86.24,  "name": "Honduras"},
    "JM": {"lat":  18.11, "lon": -77.30,  "name": "Jamaïque"},
    "MX": {"lat":  23.63, "lon": -102.55, "name": "Mexique"},
    "NI": {"lat":  12.87, "lon": -85.21,  "name": "Nicaragua"},
    "PA": {"lat":   8.54, "lon": -80.78,  "name": "Panama"},
    "PY": {"lat": -23.44, "lon": -58.44,  "name": "Paraguay"},
    "PE": {"lat":  -9.19, "lon": -75.02,  "name": "Pérou"},
    "PR": {"lat":  18.22, "lon": -66.59,  "name": "Porto Rico"},
    "TT": {"lat":  10.69, "lon": -61.22,  "name": "Trinité-et-Tobago"},
    "US": {"lat":  37.09, "lon": -95.71,  "name": "États-Unis"},
    "UY": {"lat": -32.52, "lon": -55.77,  "name": "Uruguay"},
    "VE": {"lat":   6.42, "lon": -66.59,  "name": "Venezuela"},
    # ── Asie ─────────────────────────────────────────────────────────
    "AF": {"lat":  33.94, "lon":  67.71,  "name": "Afghanistan"},
    "AM": {"lat":  40.07, "lon":  45.04,  "name": "Arménie"},
    "AZ": {"lat":  40.14, "lon":  47.58,  "name": "Azerbaïdjan"},
    "BD": {"lat":  23.68, "lon":  90.36,  "name": "Bangladesh"},
    "BT": {"lat":  27.51, "lon":  90.43,  "name": "Bhoutan"},
    "BN": {"lat":   4.94, "lon": 114.94,  "name": "Brunei"},
    "KH": {"lat":  12.57, "lon": 104.99,  "name": "Cambodge"},
    "CN": {"lat":  35.86, "lon": 104.19,  "name": "Chine"},
    "GE": {"lat":  42.32, "lon":  43.36,  "name": "Géorgie"},
    "HK": {"lat":  22.39, "lon": 114.11,  "name": "Hong Kong"},
    "IN": {"lat":  20.59, "lon":  78.96,  "name": "Inde"},
    "ID": {"lat":  -0.79, "lon": 113.92,  "name": "Indonésie"},
    "IR": {"lat":  32.43, "lon":  53.69,  "name": "Iran"},
    "IQ": {"lat":  33.22, "lon":  43.68,  "name": "Irak"},
    "IL": {"lat":  31.05, "lon":  34.85,  "name": "Israël"},
    "JP": {"lat":  36.20, "lon": 138.25,  "name": "Japon"},
    "JO": {"lat":  30.59, "lon":  36.24,  "name": "Jordanie"},
    "KZ": {"lat":  48.02, "lon":  66.92,  "name": "Kazakhstan"},
    "KW": {"lat":  29.31, "lon":  47.48,  "name": "Koweït"},
    "KG": {"lat":  41.20, "lon":  74.77,  "name": "Kirghizistan"},
    "LA": {"lat":  19.86, "lon": 102.50,  "name": "Laos"},
    "LB": {"lat":  33.85, "lon":  35.86,  "name": "Liban"},
    "MY": {"lat":   4.21, "lon": 101.98,  "name": "Malaisie"},
    "MV": {"lat":   3.20, "lon":  73.22,  "name": "Maldives"},
    "MN": {"lat":  46.86, "lon": 103.85,  "name": "Mongolie"},
    "MM": {"lat":  21.91, "lon":  95.96,  "name": "Myanmar"},
    "NP": {"lat":  28.39, "lon":  84.12,  "name": "Népal"},
    "KP": {"lat":  40.34, "lon": 127.51,  "name": "Corée du Nord"},
    "OM": {"lat":  21.51, "lon":  55.92,  "name": "Oman"},
    "PK": {"lat":  30.38, "lon":  69.35,  "name": "Pakistan"},
    "PH": {"lat":  12.88, "lon": 121.77,  "name": "Philippines"},
    "QA": {"lat":  25.35, "lon":  51.18,  "name": "Qatar"},
    "SA": {"lat":  23.89, "lon":  45.08,  "name": "Arabie Saoudite"},
    "SG": {"lat":   1.35, "lon": 103.82,  "name": "Singapour"},
    "KR": {"lat":  35.91, "lon": 127.77,  "name": "Corée du Sud"},
    "LK": {"lat":   7.87, "lon":  80.77,  "name": "Sri Lanka"},
    "SY": {"lat":  34.80, "lon":  38.99,  "name": "Syrie"},
    "TW": {"lat":  23.70, "lon": 121.00,  "name": "Taïwan"},
    "TJ": {"lat":  38.86, "lon":  71.28,  "name": "Tadjikistan"},
    "TH": {"lat":  15.87, "lon": 100.99,  "name": "Thaïlande"},
    "TR": {"lat":  38.96, "lon":  35.24,  "name": "Turquie"},
    "TM": {"lat":  38.97, "lon":  59.56,  "name": "Turkménistan"},
    "AE": {"lat":  23.42, "lon":  53.85,  "name": "Émirats Arabes Unis"},
    "UZ": {"lat":  41.38, "lon":  64.59,  "name": "Ouzbékistan"},
    "VN": {"lat":  14.06, "lon": 108.28,  "name": "Vietnam"},
    "YE": {"lat":  15.55, "lon":  48.52,  "name": "Yémen"},
    # ── Europe ───────────────────────────────────────────────────────
    "AL": {"lat":  41.15, "lon":  20.17,  "name": "Albanie"},
    "AD": {"lat":  42.55, "lon":   1.52,  "name": "Andorre"},
    "AT": {"lat":  47.52, "lon":  14.55,  "name": "Autriche"},
    "BY": {"lat":  53.71, "lon":  28.00,  "name": "Biélorussie"},
    "BE": {"lat":  50.50, "lon":   4.47,  "name": "Belgique"},
    "BA": {"lat":  44.17, "lon":  17.68,  "name": "Bosnie-Herzégovine"},
    "BG": {"lat":  42.73, "lon":  25.49,  "name": "Bulgarie"},
    "HR": {"lat":  45.10, "lon":  15.20,  "name": "Croatie"},
    "CY": {"lat":  35.13, "lon":  33.43,  "name": "Chypre"},
    "CZ": {"lat":  49.82, "lon":  15.47,  "name": "République Tchèque"},
    "DK": {"lat":  56.26, "lon":   9.50,  "name": "Danemark"},
    "EE": {"lat":  58.60, "lon":  25.01,  "name": "Estonie"},
    "FI": {"lat":  61.92, "lon":  25.75,  "name": "Finlande"},
    "FR": {"lat":  46.23, "lon":   2.21,  "name": "France"},
    "DE": {"lat":  51.17, "lon":  10.45,  "name": "Allemagne"},
    "GR": {"lat":  39.07, "lon":  21.82,  "name": "Grèce"},
    "HU": {"lat":  47.16, "lon":  19.50,  "name": "Hongrie"},
    "IS": {"lat":  64.96, "lon": -19.02,  "name": "Islande"},
    "IE": {"lat":  53.41, "lon":  -8.24,  "name": "Irlande"},
    "IT": {"lat":  41.87, "lon":  12.57,  "name": "Italie"},
    "LV": {"lat":  56.88, "lon":  24.60,  "name": "Lettonie"},
    "LT": {"lat":  55.17, "lon":  23.88,  "name": "Lituanie"},
    "LU": {"lat":  49.82, "lon":   6.13,  "name": "Luxembourg"},
    "MT": {"lat":  35.94, "lon":  14.38,  "name": "Malte"},
    "MD": {"lat":  47.41, "lon":  28.37,  "name": "Moldavie"},
    "ME": {"lat":  42.71, "lon":  19.37,  "name": "Monténégro"},
    "NL": {"lat":  52.13, "lon":   5.29,  "name": "Pays-Bas"},
    "MK": {"lat":  41.61, "lon":  21.75,  "name": "Macédoine du Nord"},
    "NO": {"lat":  60.47, "lon":   8.47,  "name": "Norvège"},
    "PL": {"lat":  51.92, "lon":  19.15,  "name": "Pologne"},
    "PT": {"lat":  39.40, "lon":  -8.22,  "name": "Portugal"},
    "RO": {"lat":  45.94, "lon":  24.97,  "name": "Roumanie"},
    "RU": {"lat":  61.52, "lon": 105.32,  "name": "Russie"},
    "RS": {"lat":  44.02, "lon":  21.01,  "name": "Serbie"},
    "SK": {"lat":  48.67, "lon":  19.70,  "name": "Slovaquie"},
    "SI": {"lat":  46.15, "lon":  14.99,  "name": "Slovénie"},
    "ES": {"lat":  40.46, "lon":  -3.75,  "name": "Espagne"},
    "SE": {"lat":  60.13, "lon":  18.64,  "name": "Suède"},
    "CH": {"lat":  46.82, "lon":   8.23,  "name": "Suisse"},
    "UA": {"lat":  48.38, "lon":  31.17,  "name": "Ukraine"},
    "GB": {"lat":  55.38, "lon":  -3.44,  "name": "Royaume-Uni"},
    "UK": {"lat":  55.38, "lon":  -3.44,  "name": "Royaume-Uni"},   # alias courant
    # ── Océanie ──────────────────────────────────────────────────────
    "AU": {"lat": -25.27, "lon": 133.78,  "name": "Australie"},
    "FJ": {"lat": -17.71, "lon": 178.06,  "name": "Fidji"},
    "NZ": {"lat": -40.90, "lon": 174.89,  "name": "Nouvelle-Zélande"},
    "PG": {"lat":  -6.31, "lon": 143.96,  "name": "Papouasie-Nv-Guinée"},
}


def get_geo_coordinates(country_code: str) -> Dict[str, Any]:
    """
    Retourne les coordonnées géographiques (lat/lon) du centroïde d'un pays
    à partir de son code ISO 3166-1 alpha-2.

    Ces coordonnées sont directement exploitables par react-simple-maps
    et d3-geo côté frontend.

    Fallback neutre si le code est inconnu : position Atlantique centrale.
    """
    if not country_code:
        return {"lat": 20.0, "lon": 0.0, "name": "Origine inconnue"}
    key = country_code.upper().strip()
    return COUNTRY_CENTROIDS.get(
        key,
        {"lat": 20.0, "lon": 0.0, "name": f"Origine externe ({country_code})"},
    )


async def get_country_from_ip(ip: str, iocs_data: Optional[List[dict]] = None) -> str:
    """
    Détection multi-stratégie du pays d'origine d'une adresse IP.

    Ordre de priorité :
      1. Champ 'country' déjà présent dans les IOCs enrichis du pipeline
         (AbuseIPDB ou VirusTotal ont déjà été appelés en parallèle).
      2. Appel direct AbuseIPDB si la clé est disponible.
      3. ip-api.com (endpoint gratuit, 45 req/min, pas de clé requise).
      4. Valeur par défaut : "US".

    Renvoie un code ISO alpha-2 en majuscules.
    """
    if iocs_data is None:
        iocs_data = []

    # ── Stratégie 1 : données de l'enrichissement déjà calculé ───────
    for ioc in iocs_data:
        if not isinstance(ioc, dict):
            continue
        if ioc.get("type") != "ip":
            continue
        # Accepte l'IOC ciblé OU le premier IOC IP disponible si ip==None
        if ip and ioc.get("value") != ip:
            continue
        country = (
            (ioc.get("abuse_ipdb") or {}).get("country")
            or (ioc.get("virus_total") or {}).get("country")
        )
        if country and len(country) == 2 and country.isalpha():
            return country.upper()

    if not ip:
        return "US"

    # ── Stratégie 2 : appel direct AbuseIPDB ─────────────────────────
    if ABUSEIPDB_KEY:
        try:
            async with httpx.AsyncClient() as client:
                result  = await check_abuse_ipdb(client, "ip", ip)
                country = result.get("country")
                if country and len(country) == 2 and country.isalpha():
                    return country.upper()
        except Exception:
            pass

    # ── Stratégie 3 : ip-api.com (free tier, pas d'auth) ─────────────
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,countryCode"},
                timeout=3.0,
            )
            if resp.status_code == 200:
                data    = resp.json()
                country = data.get("countryCode", "")
                if data.get("status") == "success" and country and len(country) == 2:
                    return country.upper()
    except Exception:
        pass

    # ── Stratégie 4 : fallback par défaut ────────────────────────────
    return "US"


# Alias déprécié — gardé pour éviter de casser d'éventuels imports existants.
# Remplacer progressivement par get_geo_coordinates().
def get_svg_coordinates(country_code: str) -> dict:
    """Déprécié. Utiliser get_geo_coordinates() à la place."""
    geo = get_geo_coordinates(country_code)
    return {**geo, "cx": 100, "cy": 160}   # cx/cy fictifs — ne pas utiliser