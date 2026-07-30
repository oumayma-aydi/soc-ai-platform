from functools import lru_cache


@lru_cache()
def get_valid_mitre_ids() -> set:
    """
    Récupère l'ensemble des IDs de techniques MITRE ATT&CK réels,
    directement depuis ChromaDB (déjà indexé via ingest_rag.py).
    Évite toute dépendance au système de fichiers du conteneur.
    """
    from app.rag.retrieval import _retriever, Retriever
    import app.rag.retrieval as retrieval_module

    if retrieval_module._retriever is None:
        retrieval_module._retriever = Retriever()

    results = retrieval_module._retriever.collection.get(
        where={"source": "attack"},
        include=["metadatas"]
    )

    return {
        m.get("technique")
        for m in results["metadatas"]
        if m.get("technique")
    }