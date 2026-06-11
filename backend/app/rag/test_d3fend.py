from app.rag.loader import load_d3fend

docs = load_d3fend()

print("Total D3FEND docs:", len(docs))
print("\nExample:\n")
print(docs[0])