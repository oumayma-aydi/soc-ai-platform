from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))


from app.rag.loader import load_attack, load_d3fend, load_capec, load_cisa, load_owasp
from app.rag.chunker import chunk_documents
from app.rag.embedder import EmbeddingService
from app.rag.indexer import ChromaIndexer

print("Loading all sources...")

docs = []

docs.extend(load_attack())
docs.extend(load_d3fend())
docs.extend(load_capec())
docs.extend(load_cisa())
docs.extend(load_owasp())

print(f"{len(docs)} docs loaded")

print("Chunking...")

chunks = chunk_documents(docs)

print(f"{len(chunks)} chunks created")

print("Embedding...")

embedder = EmbeddingService()

embeddings = embedder.embed_texts(
    [chunk["content"] for chunk in chunks]
)

print("Indexing...")

indexer = ChromaIndexer()

indexer.add_chunks(
    chunks,
    embeddings
)

print("Done.")