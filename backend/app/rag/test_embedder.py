from app.rag.embedder import EmbeddingService

embedder = EmbeddingService()

vector = embedder.embed_query(
    "brute force credentials"
)

print(len(vector))