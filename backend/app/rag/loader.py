import json
from pathlib import Path
import xml.etree.ElementTree as ET

PROJECT_ROOT = Path(__file__).resolve().parents[3]

#partie mitre attack pour la classification des incidents, agents triage mapping et killchain
def load_attack():
    """
    Charge les techniques ATT&CK depuis enterprise-attack.json
    et retourne une liste de documents.
    """
    attack_file = (
        PROJECT_ROOT
        / "data"
        / "raw"
        / "attack"
        / "enterprise-attack.json"
    )

    print("Loading:", attack_file)
    
    with open(attack_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(attack_file)
    documents = []

    for obj in data["objects"]:

        # On garde seulement les techniques ATT&CK
        if obj.get("type") != "attack-pattern":
            continue

        title = obj.get("name", "")

        description = ""

        if "description" in obj:
            description = obj["description"]

        technique_id = None

        for ref in obj.get("external_references", []):

            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        documents.append(
            {
                "title": title,
                "content": description,
                "source": "attack",
                "technique": technique_id,
            }
        )

    return documents


#partie defend pour remédiation
def load_d3fend():
    """
    Load MITRE D3FEND ontology and convert it into RAG documents
    """

    d3fend_file = (
        PROJECT_ROOT
        / "data"
        / "raw"
        / "d3fend"
        / "d3fend.json"
    )

    print("Loading:", d3fend_file)

    with open(d3fend_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = []

    for node in data.get("@graph", []):

        label = node.get("rdfs:label")
        definition = node.get("d3f:definition")

        # Certains champs D3FEND sont des listes
        if isinstance(definition, list):
            definition = " ".join(
                str(x) for x in definition
            )

        if definition is not None and not isinstance(definition, str):
            definition = str(definition)

        # Ignorer les entrées inutiles
        if not label or not definition:
            continue

        node_id = node.get("@id", "").replace("d3f:", "")

        docs.append(
            {
                "title": str(label),
                "content": definition,
                "source": "d3fend",
                "id": node_id,
            }
        )

    return docs

#Enrichissement du contexte de l'agent Triage et killchain
def load_capec():
    """
    Charge les patterns d'attaque CAPEC depuis capec.xml
    """
    capec_file = (
        PROJECT_ROOT
        / "data"
        / "raw"
        / "capec"
        / "capec.xml"
    )

    print("Loading:", capec_file)

    tree = ET.parse(capec_file)
    root = tree.getroot()

    docs = []

    for pattern in root.iter():
        if "Attack_Pattern" not in pattern.tag:
            continue

        capec_id = pattern.get("ID", "")
        name = pattern.get("Name", "")

        # Description
        description = ""
        for child in pattern.iter():
            if "Description" in child.tag and child.text:
                description = child.text.strip()
                break

        # Mitigations
        mitigations = ""
        for child in pattern.iter():
            if "Mitigation" in child.tag and child.text:
                mitigations = child.text.strip()
                break

        if not description:
            continue

        content = f"{name}. {description}"
        if mitigations:
            content += f" Mitigations: {mitigations}"

        docs.append({
            "title": name,
            "content": content,
            "source": "capec",
            "technique": f"CAPEC-{capec_id}"
        })

    print(f"CAPEC: {len(docs)} patterns loaded")
    return docs

#Contexte sur les campagnes actives
def load_cisa():
    """
    Charge les vulnérabilités exploitées CISA KEV depuis cisa_kev.json
    """
    cisa_file = (
        PROJECT_ROOT
        / "data"
        / "raw"
        / "cisa"
        / "cisa_kev.json"
    )

    print("Loading:", cisa_file)

    with open(cisa_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = []

    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        product = vuln.get("product", "")
        vendor = vuln.get("vendorProject", "")
        description = vuln.get("shortDescription", "")
        action = vuln.get("requiredAction", "")
        due_date = vuln.get("dueDate", "")

        content = (
            f"CVE: {cve_id}. "
            f"Product: {vendor} {product}. "
            f"Description: {description}. "
            f"Required Action: {action}. "
            f"Due Date: {due_date}."
        )

        docs.append({
            "title": f"{cve_id} - {product}",
            "content": content,
            "source": "cisa",
            "technique": cve_id
        })

    print(f"CISA: {len(docs)} vulnerabilities loaded")
    return docs

#Analyse des incidents web / API
def load_owasp():
    """
    Charge les catégories OWASP Top 10 depuis owasp_top10.json
    """
    owasp_file = (
        PROJECT_ROOT
        / "data"
        / "raw"
        / "owasp"
        / "owasp_top10.json"
    )

    print("Loading:", owasp_file)

    with open(owasp_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = []

    for item in data:
        docs.append({
            "title": f"OWASP {item['id']} - {item['title']}",
            "content": item["content"],
            "source": "owasp",
            "technique": item["id"]
        })

    print(f"OWASP: {len(docs)} categories loaded")
    return docs