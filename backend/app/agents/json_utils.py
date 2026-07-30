import json
import re


def parse_llm_json(raw: str) -> dict:
    """
    Parse la réponse JSON d'un LLM de façon résiliente.
    Gère le cas fréquent où le modèle recopie un chemin Windows
    (ex: \\SERVER\share\folder\) sans échapper correctement les
    backslashes, ce qui casse json.loads() en JSON standard.
    """
    text = raw.strip()

    if "```" in text:
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Réparation : échappe tout backslash qui n'est pas déjà
        # une séquence d'échappement JSON valide (\", \\, \/, \b, \f, \n, \r, \t, \uXXXX)
        repaired = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)
        return json.loads(repaired)  # laisse remonter l'exception si toujours invalide