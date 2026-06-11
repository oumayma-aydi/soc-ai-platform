import chromadb


class ChromaIndexer:

    def __init__(self):
        self.client = chromadb.HttpClient(
            host="localhost",
            port=8001
        )
        self.collection = self.client.get_or_create_collection(
            name="soc_knowledge_base"
        )

    def add_chunks(self, chunks, embeddings, batch_size=500):

        ids = []
        documents = []
        metadatas = []

        for i, chunk in enumerate(chunks):
            ids.append(f"chunk_{i}")
            documents.append(chunk["content"])
            metadatas.append(chunk["metadata"])

        embeddings_list = embeddings.tolist()

        # Découper en batches de 500
        total = len(ids)
        for start in range(0, total, batch_size):
            end = min(start + batch_size, total)
            print(f"Indexing batch {start}-{end} / {total}")
            self.collection.add(
                ids=ids[start:end],
                documents=documents[start:end],
                metadatas=metadatas[start:end],
                embeddings=embeddings_list[start:end]
            )