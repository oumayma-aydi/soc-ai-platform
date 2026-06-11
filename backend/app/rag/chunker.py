from langchain_text_splitters import RecursiveCharacterTextSplitter


def chunk_documents(documents):
    """
    Découpe les documents en chunks.
    """

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=512,
        chunk_overlap=50
    )

    chunks = []

    for doc in documents:

        text_chunks = splitter.split_text(
            doc["content"]
        )

        for chunk in text_chunks:

            metadata = {
                "title": doc["title"],
                "source": doc["source"]
            }

            # ATT&CK
            if "technique" in doc:
                metadata["technique"] = doc["technique"]

            # D3FEND
            if "id" in doc:
                metadata["id"] = doc["id"]

            chunks.append(
                {
                    "content": chunk,
                    "metadata": metadata
                }
            )

    return chunks