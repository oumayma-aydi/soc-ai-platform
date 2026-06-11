from app.rag.loader import load_attack
from app.rag.chunker import chunk_documents

docs = load_attack()

chunks = chunk_documents(docs)

print(f"Documents : {len(docs)}")
print(f"Chunks : {len(chunks)}")

print("\nPremier chunk :\n")

print(chunks[0])