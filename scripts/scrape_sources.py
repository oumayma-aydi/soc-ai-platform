import requests
from bs4 import BeautifulSoup
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "raw"


def scrape_owasp():
    print("Scraping OWASP Top 10...")
    categories = [
        ("A01", "Broken Access Control", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
        ("A02", "Cryptographic Failures", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
        ("A03", "Injection", "https://owasp.org/Top10/A03_2021-Injection/"),
        ("A04", "Insecure Design", "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
        ("A05", "Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
        ("A06", "Vulnerable Components", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
        ("A07", "Auth Failures", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
        ("A08", "Software Integrity Failures", "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
        ("A09", "Logging Failures", "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
        ("A10", "SSRF", "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
    ]

    results = []
    for code, name, url in categories:
        try:
            r = requests.get(url, timeout=15)
            soup = BeautifulSoup(r.text, "lxml")
            content_div = soup.find("div", class_="sect1") or soup.find("main") or soup.find("article")
            text = content_div.get_text(separator=" ", strip=True) if content_div else soup.get_text(separator=" ", strip=True)[:3000]
            results.append({"id": code, "title": name, "content": text[:4000], "url": url})
            print(f"  ✓ {code} - {name}")
        except Exception as e:
            print(f"  ✗ {code} - {name} : {e}")

    out = DATA_DIR / "owasp" / "owasp_top10.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"OWASP saved → {out} ({len(results)} categories)")


if __name__ == "__main__":
    scrape_owasp()
    print("\nOWASP ready.")