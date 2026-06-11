from sentence_transformers import SentenceTransformer


class EmbeddingService:
    """
    Service unique d'embedding pour tout le projet.
    """

    def __init__(self):
        self.model = SentenceTransformer(
            "all-MiniLM-L6-v2"
        )

    def embed_texts(self, texts):
        return self.model.encode(
            texts,
            convert_to_numpy=True
        )

    def embed_query(self, query):
        return self.model.encode(
            query,
            convert_to_numpy=True
        )