import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from app.enrichment.ioc_service import enrich_ioc

async def main():
    print("=" * 60)
    print("Testing Parallel IOC Enrichment")
    print("=" * 60)
    
    # IP de test (par exemple, une IP connue pour du trafic suspect ou une IP publique standard)
    test_ip = "185.220.101.47" # IP mentionnée dans ton scénario brute force !
    
    start_time = time.time()
    result = await enrich_ioc("ip", test_ip)
    duration = time.time() - start_time
    
    print(f"\nAnalyse de l'IP : {test_ip}")
    print(f"Temps d'exécution : {duration:.2f} secondes")
    print("-" * 40)
    
    import json
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())