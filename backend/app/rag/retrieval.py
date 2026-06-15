import chromadb

from app.rag.embedder import (
    EmbeddingService
)


class Retriever:

    def __init__(self):

        self.embedder = EmbeddingService()

        self.client = chromadb.HttpClient(
            host="localhost",
            port=8001
        )

        self.collection = self.client.get_collection(
            "soc_knowledge_base"
        )

    def retrieve(
        self,
        query,
        top_k=5
    ):

        query_embedding = (
            self.embedder.embed_query(
                query
            )
        )

        results = self.collection.query(
            query_embeddings=[
                query_embedding.tolist()
            ],
            n_results=top_k
        )

        return results
    

# Instance globale réutilisable
_retriever = None

def retrieve(query, top_k=5):
    global _retriever
    if _retriever is None:
        _retriever = Retriever()
    
    results = _retriever.retrieve(query, top_k)
    
    # Formater pour test_rag.py
    formatted = []
    for i in range(len(results["documents"][0])):
        formatted.append({
            "content": results["documents"][0][i],
            "metadata": results["metadatas"][0][i],
            "distance": results["distances"][0][i]
        })
    
    return formatted