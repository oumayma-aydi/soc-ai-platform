import asyncio
import sys
import os
import httpx
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from dotenv import load_dotenv

load_dotenv()
OTX_KEY = os.getenv("OTX_API_KEY")

async def debug_raw_otx():
    test_ip = "185.220.101.47"
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{test_ip}/general"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    
    print("Envoi de la requête à AlienVault OTX (Timeout étendu à 30s)...")
    
    async with httpx.AsyncClient() as client:
        try:
            # On lui laisse 30 secondes pour répondre
            response = await client.get(url, headers=headers, timeout=30.0)
            print(f"Statut HTTP reçu : {response.status_code}")
            
            if response.status_code == 200:
                print("\n--- RÉPONSE BRUTE OTX MÊME SI LENTE ---")
                # On affiche juste les 20 premières lignes pour ne pas inonder le terminal
                data = response.json()
                print(json.dumps(data, indent=2)[:2000]) 
                print("\n... (tronqué pour l'affichage) ...")
            else:
                print(f"Erreur de l'API OTX: {response.text}")
                
        except httpx.TimeoutException:
            print("Même avec 30 secondes, l'API OTX a expiré ! Le problème vient du réseau ou du blocage de l'IP publique.")
        except Exception as e:
            print(f"Erreur : {e}")

if __name__ == "__main__":
    asyncio.run(debug_raw_otx())