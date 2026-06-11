from app.rag.loader import load_attack

docs = load_attack()

print(f"Documents chargés : {len(docs)}")

print("\nPremier document :\n")

print(docs[0])