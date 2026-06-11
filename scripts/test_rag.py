import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.rag.retrieval import retrieve

queries = [
    "phishing email credential theft",
    "brute force password spraying",
    "account takeover insurance fraud",
    "sql injection web application",
]

print("=" * 60)
print("RAG Multi-Source Retrieval Test")
print("=" * 60)

for query in queries:
    print(f"\nQuery: '{query}'")
    print("-" * 40)
    results = retrieve(query, top_k=3)
    for i, r in enumerate(results):
        source = r["metadata"].get("source", "unknown")
        technique = r["metadata"].get("technique", "")
        title = r["metadata"].get("title", "")
        print(f"  {i+1}. [{source.upper()}] {technique} - {title}")