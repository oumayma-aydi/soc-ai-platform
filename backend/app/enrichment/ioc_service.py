import os
import asyncio
import httpx
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")

TIMEOUT = 5.0 # Timeout de 5 secondes par source (Cahier des charges)

async def check_virus_total(client: httpx.AsyncClient, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Interroge l'API VirusTotal v3 pour une IP, un domaine ou un hash."""
    if not VIRUSTOTAL_KEY:
        return {"error": "API Key manquante"}
    
    # Adapter l'endpoint selon le type d'IOC
    endpoint_map = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {"error": f"Type d'IOC non supporté par VT: {ioc_type}"}

    headers = {"x-apikey": VIRUSTOTAL_KEY}
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc_value}"
    
    try:
        response = await client.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious_score": stats.get("malicious", 0),
                "harmless_score": stats.get("harmless", 0),
                "category": data.get("attributes", {}).get("categories", {})
            }
        return {"status_code": response.status_code, "error": response.text}
    except Exception as e:
        return {"error": str(e)}

async def check_abuse_ipdb(client: httpx.AsyncClient, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Interroge l'API AbuseIPDB pour les adresses IP uniquement."""
    if ioc_type != "ip":
        return {} # AbuseIPDB ne traite que les IPs
    if not ABUSEIPDB_KEY:
        return {"error": "API Key manquante"}

    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc_value, "maxAgeInDays": "90"}
    url = "https://api.abuseipdb.com/api/v2/check"

    try:
        response = await client.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "total_reports": data.get("totalReports", 0)
            }
        return {"status_code": response.status_code, "error": response.text}
    except Exception as e:
        return {"error": str(e)}

async def check_alienvault_otx(client: httpx.AsyncClient, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Interroge l'API AlienVault OTX (Threat Intelligence OSINT)."""
    if not OTX_KEY:
        return {"error": "API Key manquante"}

    endpoint_map = {"ip": "IPv4", "domain": "domain", "hash": "file"}
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {"error": f"Type d'IOC non supporté par OTX: {ioc_type}"}

    headers = {"X-OTX-API-KEY": OTX_KEY}
    url = f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/{ioc_value}/general"

    try:
        response = await client.get(url, headers=headers, timeout=30.0)
        
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            
            # Extraction sécurisée des tags
            tags = []
            for p in pulses:
                for tag in p.get("tags", []):
                    if tag and tag not in tags:
                        tags.append(tag)
            
            return {
                "pulse_count": pulse_info.get("count", 0),
                "references": [p.get("name") for p in pulses[:3]], # Top 3 des menaces
                "tags": tags[:5]
            }
            
        return {"status_code": response.status_code, "error": f"Erreur API OTX: {response.text[:100]}"}
        
    except httpx.TimeoutException:
        return {"error": "Timeout de 5s atteint pour AlienVault OTX"}
    except Exception as e:
        return {"error": f"Erreur inattendue OTX: {str(e)}"}

async def enrich_ioc(ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Lance les requêtes OSINT en parallèle grâce à asyncio.gather()."""
    async with httpx.AsyncClient() as client:
        # Lancement simultané des trois tâches
        tasks = [
            check_virus_total(client, ioc_type, ioc_value),
            check_abuse_ipdb(client, ioc_type, ioc_value),
            check_alienvault_otx(client, ioc_type, ioc_value)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Formatage du résultat final consolidé
        return {
            "ioc": ioc_value,
            "type": ioc_type,
            "virus_total": results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])},
            "abuse_ipdb": results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])},
            "alienvault_otx": results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])}
        }