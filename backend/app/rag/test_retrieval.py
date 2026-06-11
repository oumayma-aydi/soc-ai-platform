from app.rag.retrieval import Retriever

retriever = Retriever()

results = retriever.retrieve(
    "brute force credentials"
)

for i in range(len(results["documents"][0])):

    print("\n" + "=" * 80)

    print(
        f"Technique : "
        f"{results['metadatas'][0][i]['technique']}"
    )

    print(
        f"Titre : "
        f"{results['metadatas'][0][i]['title']}"
    )

    print(
        f"Distance : "
        f"{results['distances'][0][i]}"
    )

    print("\nExtrait :")

    print(
        results["documents"][0][i][:300]
    )