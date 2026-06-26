import asyncio
import httpx
from app.config import get_settings

settings = get_settings()

async def fetch_virus_total(client: httpx.AsyncClient, ioc_value: str) -> dict:
    """Interroge l'API VirusTotal v3 pour un IOC donné avec un timeout de 5s."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    try:
        response = await client.get(url, headers=headers, timeout=5.0)
        if response.status_code == 200:
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious_score": stats.get("malicious", 0),
                "harmless_score": stats.get("harmless", 0)
            }
    except Exception:
        pass
    return {"malicious_score": 0, "harmless_score": 0}

async def fetch_abuse_ipdb(client: httpx.AsyncClient, ioc_value: str) -> dict:
    """Interroge l'API AbuseIPDB v2 pour une adresse IP avec un timeout de 5s."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ioc_value, "maxAgeInDays": "90"}
    try:
        response = await client.get(url, headers=headers, params=params, timeout=5.0)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "UNKNOWN"),
                "isp": data.get("isp", "Unknown ISP")
            }
    except Exception:
        pass
    return {"abuse_score": 0, "country": "UNKNOWN", "isp": "Unknown ISP"}

async def enrich_all_iocs(iocs_list: list) -> dict:
    """
    Prend une liste d'IOCs (dictionnaires ou objets), filtre les adresses IP,
    et lance les requêtes VirusTotal + AbuseIPDB en parallèle via asyncio.gather().
    """
    enrichment_result = {}
    
    # On isole uniquement les adresses IP pour ce traitement
    ip_values = [ioc.value if hasattr(ioc, 'value') else ioc.get('value') 
                 for ioc in iocs_list if (hasattr(ioc, 'type') and ioc.type == 'ip') or (isinstance(ioc, dict) and ioc.get('type') == 'ip')]

    if not ip_values:
        return enrichment_result

    async with httpx.AsyncClient() as client:
        for ip in ip_values:
            # Lancement des deux APIs en parallèle pour chaque IP
            vt_task = fetch_virus_total(client, ip)
            abuse_task = fetch_abuse_ipdb(client, ip)
            
            vt_res, abuse_res = await asyncio.gather(vt_task, abuse_task)
            
            enrichment_result[ip] = {
                "virus_total": vt_res,
                "abuse_ipdb": abuse_res
            }
            
    return enrichment_result
