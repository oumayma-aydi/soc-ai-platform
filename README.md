# SOC AI Platform — STAR Assurances

> **Note pour l'IA qui reprend ce projet** : ce document est un état des lieux complet, écrit pour te permettre de continuer le développement sans reposer les mêmes questions à la personne qui pilote ce projet. Lis-le entièrement avant de proposer du code. Les sections "Ce qui est fait", "Bugs connus" et "Ce qu'il reste à faire" sont les plus importantes.

---

## 1. But du projet et problématique

Stage en entreprise (secteur assurance, STAR Assurances, Tunisie), durée 8 semaines, actuellement en **semaine 4-5 sur 8**.

**Problème à résoudre** : les compagnies d'assurance font face en continu à des menaces cyber (phishing, vol de credentials, fraude, accès non autorisé aux données clients). L'équipe sécurité de STAR a besoin d'un outil qui prend un log brut ou une alerte en entrée, et produit automatiquement :
- une classification de la menace avec mappage MITRE ATT&CK
- une reconstruction de la chaîne d'attaque (kill chain) avec timeline
- un enrichissement des IOCs (IPs, domaines, hashes) via des sources OSINT
- un rapport d'analyse complet avec recommandations de remédiation et score de sévérité

**Contrainte de sécurité centrale, explicitement demandée par le manager sécurité (l'encadrant du stage)** : la plateforme elle-même ne doit jamais envoyer de données sensibles (identifiants de contrats, e-mails clients) à un LLM externe (Groq). Seules les données techniques nécessaires (adresses IP, types de techniques) sont transmises, après une couche de sanitization RGPD.

**Priorité réelle clarifiée par l'encadrant en cours de stage** : le besoin numéro un est "donner un incident à la plateforme, obtenir une explication claire et des actions de remédiation fiables" — pas l'intégration SIEM (Wazuh), qui reste secondaire.

---

## 2. Architecture globale

Pipeline séquentiel à 9 couches :

| # | Couche | Rôle | Techs |
|---|---|---|---|
| 1 | Frontend React | Interface analyste : threat map, analyse, rapports, dashboard, gestion des comptes | React 18/19, Tailwind CSS, Axios, d3-geo, topojson-client |
| 2 | API Gateway | Point d'entrée HTTP, JWT, routage | FastAPI, Python 3.12 |
| 3 | Sanitization Layer | Nettoyage RGPD, anti prompt-injection | Regex, Pydantic v2 |
| 4 | IOC Enrichment | Enrichissement parallèle IP/domaine/hash | VirusTotal, AbuseIPDB, AlienVault OTX (asyncio) |
| 5 | RAG Knowledge Base | Base de connaissances indexée | ChromaDB, Sentence-BERT, LangChain |
| 6 | Multi-Agent Pipeline | 4 agents IA en séquence (Triage → Mapping → Kill Chain → Remediation) | LangGraph, Groq (Llama 3.3) |
| 7 | Confidence Scoring | Score de cohérence de l'analyse | Scoring déterministe multi-dimensions |
| 8 | Report Engine | Génération PDF + Live Threat Map | ReportLab, SVG/d3-geo |
| 9 | Data Storage | Stockage incidents, comptes, historique | PostgreSQL (JSONB), Redis |

**Infrastructure** : Kubernetes (Minikube en dev), namespace `soc-platform`. Pivot depuis Docker Compose décidé en semaine 1 suite à une réunion avec les managers Sécurité et DevOps, pour s'aligner sur l'infra cible de production.

**Flux de données principal** :
```
Log brut → Sanitization (anti-jailbreak, RGPD) → Enrichissement IOC (asyncio.gather)
  → Agent Triage → Agent Mapping → Agent Kill Chain → Agent Remediation
  → Confidence Scoring → Persistance PostgreSQL (JSONB) → Rapport JSON + PDF
```

---

## 3. Arborescence du projet

```
soc-ai-platform/
├── backend/
│   ├── app/
│   │   ├── agents/              # pipeline.py (orchestration LangGraph), triage.py, mapping.py,
│   │   │                        # kill_chain.py, remediation.py
│   │   ├── api/
│   │   │   ├── routes/          # auth.py (login, register, gestion comptes, mot de passe oublié),
│   │   │   │                    # health.py
│   │   │   └── endpoints/       # incidents.py (analyze, live-threats, export-pdf, list)
│   │   ├── core/                # database.py, security.py (JWT, bcrypt), dependencies.py (RBAC)
│   │   ├── enrichment/          # ioc_service.py (VirusTotal/AbuseIPDB/OTX clients + géocodage)
│   │   ├── models/              # orm.py (SQLAlchemy: UserORM, IncidentORM, PasswordResetRequestORM)
│   │   ├── schemas/              # auth.py (Pydantic UNIQUEMENT — jamais de routes ici),
│   │   │                        # incident.py
│   │   ├── services/            # user_service.py, email_service.py, pdf_service.py
│   │   ├── rag/                 # retrieval.py, ingestion ChromaDB
│   │   └── config.py            # Settings (pydantic-settings, lit .env)
│   ├── alembic/                 # migrations DB
│   ├── scripts/                 # create_first_admin.py
│   ├── Dockerfile
│   ├── requirements-docker.txt  # ⚠️ CPU-only, à utiliser TOUJOURS pour Docker/déploiement
│   └── requirements.txt         # ⚠️ contient des dépendances CUDA/GPU — NE JAMAIS installer
│                                #    tel quel sur un poste sans GPU dédié
├── frontend/
│   ├── src/
│   │   ├── pages/               # Home.jsx (Live Threat Map), Dashboard.jsx, Analysis.jsx,
│   │   │                        # Report.jsx, Login.jsx, ForgotPassword.jsx, ResetPassword.jsx,
│   │   │                        # UserManagement.jsx
│   │   ├── components/          # Sidebar.jsx
│   │   ├── api/                 # client.js (axios + intercepteurs JWT)
│   │   ├── utils/                # severity.js (source unique de vérité des couleurs/labels de sévérité)
│   │   └── App.jsx              # routes + PrivateLayout (garde d'authentification)
│   └── package.json
├── k8s/
│   ├── namespace.yaml
│   ├── backend/                 # deployment.yaml, service.yaml, configmap.yaml,
│   │                            # secret.yaml (JAMAIS commit — voir section 6), secret.yaml.example
│   ├── postgres/                # statefulset.yaml, service.yaml, pvc.yaml, secret.yaml (JAMAIS commit)
│   ├── redis/                   # statefulset.yaml, service.yaml, pvc.yaml
│   └── chromadb/                # statefulset.yaml, service.yaml, pvc.yaml
├── data/
│   └── raw/                     # ATT&CK JSON, CAPEC, D3FEND téléchargés (sources RAG)
└── .gitignore
```

---

## 4. Ce qui est fait (état détaillé, semaine 4-5)

### Backend / Pipeline IA — opérationnel de bout en bout
- Pipeline complet Sanitization → Enrichissement → 4 agents LangGraph → Scoring → Persistance, déployé en Kubernetes
- RAG avec **11 688 chunks** indexés (MITRE ATT&CK, D3FEND, CAPEC, CISA, OWASP) dans ChromaDB
- Enrichissement IOC parallèle (VirusTotal + AbuseIPDB + AlienVault OTX via `asyncio.gather`), avec filtrage des IPs privées (RFC 1918) — **voir bug connu ci-dessous, le filtre actuel est buggé**
- Sanitization RGPD (retrait e-mails/IDs de contrats avant envoi au LLM externe) + validateur Pydantic anti-jailbreak (décodage Base64, normalisation Unicode NFKC, blocage HTML/XML, mots-clés de jailbreak) — validé à 100% sur script de test hardcore
- Confidence Scoring déterministe implémenté et affiché

### Live Cyber Threat Map — fonctionnalité ajoutée, non prévue au cahier des charges initial
- Géolocalisation réelle de l'IP source en cascade à 3 stratégies : IOCs du pipeline → AbuseIPDB direct → ip-api.com (fallback gratuit)
- 130+ centroïdes de pays (lat/lon) dans `ioc_service.py` (fonction `get_geo_coordinates`)
- Rendu carte via **d3-geo + topojson-client** en SVG manuel (PAS react-simple-maps — abandonné car incompatible peer-deps avec React 19)
- Polling frontend toutes les 5s sur `/api/incidents/live-threats`

### Authentification & gestion des comptes
- JWT (access 1h + refresh 7j), RBAC à 3 rôles (admin / analyst / auditor)
- **Un seul compte admin autorisé** — bloqué à la fois côté création (`create_user`) et changement de rôle (`update_user_role`)
- Page `UserManagement.jsx` (visible uniquement pour l'admin) : création de comptes, liste des comptes (sans jamais exposer le mot de passe — bcrypt est à sens unique, aucune consultation possible par design), changement de rôle, changement d'e-mail, réinitialisation de mot de passe, suppression
- **Ré-authentification obligatoire** (mot de passe admin ressaisi) avant toute action sensible : changement de rôle, reset de mot de passe, suppression de compte
- Blocage automatique après **3 tentatives de connexion échouées** (`MAX_FAILED_ATTEMPTS`), avec notification e-mail automatique aux admins + route de déblocage manuel
- Mot de passe oublié à deux parcours : admin → lien de réinitialisation auto-service par e-mail ; analyst/auditor → notification à l'admin qui traite manuellement (pas d'auto-service pour ces rôles)
- Service e-mail SMTP générique (`email_service.py`), configuré via Gmail + mot de passe d'application (pas le mot de passe du compte)

### Sécurité plateforme
- Politique de mot de passe ANSSI (12+ caractères, majuscule, minuscule, chiffre, caractère spécial)
- Historique des 5 derniers mots de passe (non réutilisables)
- Expiration de mot de passe à 60 jours
- Secrets (.env, secret.yaml) volontairement absents du repo Git

### Charte graphique UI (design system strict, ajouté au cahier des charges initial)
- Vert institutionnel STAR `#00664F`, fond blanc/gris clair, accents de sévérité sobres (rouge mat `#991B1B`, orange mat `#C2410C`, bleu ardoise `#1E3A8A`)
- Aucun emoji, aucune esthétique cyberpunk/néon, source unique de vérité pour les couleurs de sévérité dans `frontend/src/utils/severity.js`

---

## 5. Bugs connus — À CORRIGER EN PRIORITÉ

### 🔴 Bug critique confirmé par un test avec l'encadrant — filtre IP privées cassé
Dans `backend/app/api/endpoints/incidents.py`, le filtre actuel :
```python
public_ips = [ip for ip in all_ips if not ip.startswith(("127.", "192.168.", "10.", "172.16."))]
```
ne filtre que `172.16.x.x` littéralement, pas toute la plage privée RFC 1918 (`172.16.0.0` à `172.31.255.255`). Une IP interne comme `172.23.48.247` passe au travers et a été confondue avec l'IP de l'attaquant lors d'un test réel, menant à une recommandation absurde ("bloquer cette IP au firewall" alors que c'est une IP interne à STAR).

**Correctif à appliquer** (remplacer partout où ce pattern apparaît, y compris potentiellement dans `ioc_service.py`) :
```python
import ipaddress

def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return True

public_ips = [ip for ip in all_ips if not is_private_ip(ip)]
```

### 🔴 Aucune extraction de domaines/URLs dans le pipeline
Seules les adresses IP sont extraites par regex. Pour un incident de phishing, l'IOC le plus actionnable est souvent le **domaine** de la page malveillante, pas l'IP du relais SMTP (qui peut être un serveur légitime compromis, non lié à l'attaquant). Résultat observé : l'agent Remediation recommande de bloquer une IP par défaut faute de domaine disponible en IOC.

**À ajouter** : extraction de domaines/URLs (regex `https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`) en plus des IP, puis enrichissement via VirusTotal (l'endpoint `domains` existe déjà dans `ioc_service.py`, jamais appelé en pratique avec un vrai domaine).

### 🟡 Kill Chain répète la même phase plusieurs fois
Observé en test réel : la Kill Chain affichait "Initial Access" 6 fois d'affilée au lieu de progresser à travers différentes phases ATT&CK. Cause probable : prompt de l'agent Kill Chain pas assez contraint sur la diversité des phases. À investiguer dans `backend/app/agents/kill_chain.py`.

### 🟡 Directive de remédiation "bloquer domaine, pas IP" pas assez robuste
Une correction avait déjà été faite une fois (directive RAG ajoutée pour prioriser le blocage de domaine sur les incidents de messagerie), mais le même problème est réapparu sur un nouveau test. La correction précédente était probablement trop spécifique à un scénario RAG (retrouvée par similarité sémantique, donc pas systématique). **Il faut une règle déterministe dans le prompt système de l'agent Remediation**, appliquée à chaque fois que `incident_type` contient "Phishing", indépendamment de ce que retrouve la recherche vectorielle.

### 🟡 Sévérité de phishing peut-être sous-évaluée
Un test réel a donné 2/10 pour un spearphishing ciblé avec SPF/DKIM/DMARC valides (donc un e-mail qui a l'air parfaitement légitime — plus dangereux qu'un phishing grossier). À envisager : un plancher de sévérité déterministe dans l'agent Triage pour ce cas de figure, plutôt que de laisser le LLM improviser librement.

### 🟡 Dashboard — colonne "Urgence" toujours "Basse"
`Dashboard.jsx` n'utilise pas la fonction partagée `getUrgencyLabel()` de `utils/severity.js` — à uniformiser sur cette source unique de vérité, déjà utilisée correctement par `Home.jsx` et `Report.jsx`.

### 🟢 Déjà corrigé — mismatch de nom d'image Docker
Le déploiement Kubernetes référence `soc-backend:latest`. **Toujours builder sous ce nom exact**, jamais `soc-ai-backend` (erreur qui a coûté plusieurs heures de debug — le pod tournait sur une vieille image sans jamais planter ni erreur visible).

---

## 6. Fichiers à recréer manuellement (jamais dans le repo Git, volontairement)

Ces fichiers sont dans `.gitignore` et doivent être recréés à la main sur chaque nouvel environnement, depuis un gestionnaire de mots de passe — jamais copiés depuis une conversation ou un canal non sécurisé.

### `backend/.env`
```env
# === API KEYS (à obtenir : virustotal.com, abuseipdb.com, otx.alienvault.com, console.groq.com) ===
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
VIRUSTOTAL_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ABUSEIPDB_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
OTX_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# === DATABASE (adapter si mot de passe PostgreSQL changé) ===
POSTGRES_URL=postgresql://socuser:CHANGE_MOI@postgres:5432/socdb
REDIS_URL=redis://redis:6379/0
CHROMA_URL=http://chromadb:8000

# === SECURITY ===
JWT_SECRET=une_chaine_aleatoire_longue_generee_a_neuf_jamais_reutilisee
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# === EMAIL (Gmail — nécessite un mot de passe d'application, PAS le mot de passe du compte) ===
# Générer depuis : Compte Google > Sécurité > Validation en 2 étapes > Mots de passe des applications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=un_compte_dedie@gmail.com
SMTP_PASSWORD=mot_de_passe_application_16_caracteres
SMTP_FROM=un_compte_dedie@gmail.com
FRONTEND_URL=http://localhost:5173

# === APP ===
ENV=production
```

### `k8s/backend/secret.yaml`
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: soc-secrets
  namespace: soc-platform
type: Opaque
stringData:
  GROQ_API_KEY: "gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  VIRUSTOTAL_API_KEY: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  ABUSEIPDB_API_KEY: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  OTX_API_KEY: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  JWT_SECRET: "une_chaine_aleatoire_longue_generee_a_neuf"
  POSTGRES_URL: "postgresql://socuser:CHANGE_MOI@postgres:5432/socdb"
  REDIS_URL: "redis://redis:6379/0"
  CHROMA_URL: "http://chromadb:8000"
  SMTP_USER: "un_compte_dedie@gmail.com"
  SMTP_PASSWORD: "mot_de_passe_application_16_caracteres"
  SMTP_FROM: "un_compte_dedie@gmail.com"
```
Appliquer avec : `kubectl apply -f k8s/backend/secret.yaml -n soc-platform`

### `k8s/postgres/secret.yaml`
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: postgres-secret
  namespace: soc-platform
type: Opaque
data:
  # Valeurs en base64 : echo -n "socuser" | base64
  POSTGRES_USER: c29jdXNlcg==
  # ⚠️ Régénérer un vrai mot de passe fort, encoder en base64, ne jamais réutiliser
  # "socpassword" — ce mot de passe a fuité dans un ancien commit Git et a été considéré compromis
  POSTGRES_PASSWORD: <A_REGENERER>
```

> ⚠️ **Historique de sécurité important** : un ancien commit (`596d3c9`) avait accidentellement inclus `k8s/postgres/secret.yaml` avec le mot de passe PostgreSQL en clair (`socuser` / `socpassword`). L'historique Git a été purgé avec `git-filter-repo` et le repo repoussé en force. Si tu retrouves une copie locale antérieure à cette purge, ne la repousse jamais sur GitHub — reclone plutôt depuis `origin/main`. Le mot de passe PostgreSQL doit être régénéré et n'est plus `socpassword`.

---

## 7. Installation sur un poste neuf (résumé — voir historique de session pour le détail complet du dépannage WSL)

```bash
# 1. WSL2 (PowerShell Admin, une seule fois)
wsl --install -d Ubuntu
# Si "sudo est désactivé" ou fonctionnalités manquantes : voir section 8 (dépannage WSL)

# 2. Dans Ubuntu WSL, une fois sudo fonctionnel
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget unzip build-essential python3-pip python3-venv

# 3. Docker Engine (PAS Docker Desktop — éviter toute dépendance à des droits admin Windows)
# Le script get.docker.com peut rediriger vers Docker Desktop sous WSL ; utiliser --force si besoin,
# ou suivre https://docs.docker.com/engine/install/ubuntu/ (méthode dépôts APT) en cas de blocage
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Sortir/rentrer de WSL pour appliquer le groupe :  exit  puis  wsl

# 4. Minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
rm minikube-linux-amd64

# 5. kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# 6. Node.js via nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install --lts

# 7. Clone et secrets (voir section 6 pour recréer .env et les secret.yaml)
git clone https://github.com/oumayma-aydi/soc-ai-platform.git
cd soc-ai-platform
# recréer backend/.env, k8s/backend/secret.yaml, k8s/postgres/secret.yaml ici

# 8. Build et déploiement — IMPORTANT : toujours ce nom d'image exact
eval $(minikube docker-env)
docker build --no-cache -t soc-backend:latest ./backend
minikube start --driver=docker --memory=8192 --cpus=4
kubectl create namespace soc-platform
kubectl apply -f k8s/ -n soc-platform

# 9. Frontend
cd frontend
npm install
npm run dev
```

**Ne jamais utiliser `backend/requirements.txt` pour un `pip install` local** — il contient des dépendances CUDA/GPU (`nvidia-cuda-*`, `cuda-toolkit`) inutiles et lourdes sur un poste sans carte NVIDIA dédiée. Utiliser uniquement `requirements-docker.txt` (déjà CPU-only), et seulement si besoin de lancer des scripts de test Python hors conteneur.

---

## 8. Dépannage — pièges déjà rencontrés (pour ne pas reperdre du temps dessus)

- **`kubectl exec`/`logs` avec un nom de pod en dur** : les noms de pods changent à chaque `rollout restart`. Préférer `kubectl exec -it deployment/backend -n soc-platform -- ...` plutôt que de copier un nom de pod précis.
- **`kubectl` sans `-n soc-platform`** cherche dans le namespace `default` et renvoie des "NotFound" trompeurs. Toujours préciser le namespace.
- **Deux dossiers différents pour les routes** : `app/api/endpoints/` (incidents.py) et `app/api/routes/` (auth.py, health.py) — ne pas confondre lors d'un `grep`/`find`.
- **`app/schemas/auth.py` ne doit contenir QUE des classes Pydantic**, jamais de `@router`. Un mélange des deux a causé un `NameError`/import circulaire qui a fait planter tout le backend (`CrashLoopBackOff`) pendant plusieurs heures de debug.
- **Un champ Pydantic `Settings` sans valeur par défaut est obligatoire** — si une variable d'env manque dans le Secret K8s (ex: `SMTP_USER` ajouté sans valeur par défaut), tout le backend refuse de démarrer, même pour des routes qui n'ont rien à voir avec cette variable. Toujours donner une valeur par défaut (`= ""`) aux champs non strictement critiques.
- **Erreurs 422 de FastAPI/Pydantic renvoient `detail` comme un tableau d'objets**, pas une chaîne — un frontend qui affiche `err.response.data.detail` directement dans un `<p>` plante avec "Objects are not valid as a React child". Toujours utiliser une fonction utilitaire (`extractErrorMessage`) qui gère les deux formats (string et array).
- **`docker build` sous un nom différent de celui attendu par le Deployment K8s** ne génère aucune erreur visible — le pod continue simplement de tourner sur l'ancienne image indéfiniment. Toujours vérifier avec `kubectl get deployment backend -n soc-platform -o jsonpath='{.spec.template.spec.containers[0].image}'` que le nom correspond exactement à celui buildé.
- **`react-simple-maps` n'a aucune version compatible React 19** (peer dependency plafonnée à React 18). Solution retenue : `d3-geo` + `topojson-client` directement, sans wrapper React, pour le rendu de la carte.
- **`bcrypt` est un hash à sens unique** — aucune fonctionnalité de consultation du mot de passe en clair n'est possible, ni ne doit être développée. Seule la réinitialisation (attribution d'un nouveau mot de passe) est possible.
- **Proxy d'entreprise (si applicable)** : à configurer séparément à 4 endroits si les téléchargements échouent silencieusement : `apt`/`curl` (variables `http_proxy`/`https_proxy`), le démon Docker (`/etc/systemd/system/docker.service.d/http-proxy.conf`), `docker build --build-arg HTTP_PROXY=...`, et `npm config set proxy ...`.

---

## 9. Ce qu'il reste à faire — roadmap semaines 5 à 8

| Semaine | Axe | Détail |
|---|---|---|
| **5** | Correctifs IA prioritaires | Fix filtre IP privées (`ipaddress`), extraction domaines/URLs + enrichissement VirusTotal domain, prompt Remediation robuste (règle déterministe "domaine pas IP" pour phishing), fix Kill Chain (diversité des phases), fix urgence Dashboard |
| **5** | Sécurité plateforme | Ingress NGINX (`minikube addons enable ingress`), rate limiting (slowapi, 10/min/user), table `audit_logs` |
| **6** | Évaluation IA objective | Construire un jeu de test (10-15 incidents avec vraie classification/techniques MITRE attendues), mesurer les écarts avant d'improviser de nouvelles corrections |
| **6** | Nouvelles sources RAG | Évaluer l'ajout de sources supplémentaires demandées par l'encadrant (clarifier s'il veut dire "plus de threat intel dans le RAG" type ENISA/ANSSI/CVE-NVD, ou un lookup Kaspersky OpenTIP en plus de VirusTotal/AbuseIPDB/OTX) |
| **6** | Page IOC Lookup | Endpoint + page dédiée réutilisant `enrich_ioc()` existant, pour consulter la réputation d'une IP/domaine indépendamment d'un incident complet |
| **6** | Kill Chain Timeline React | Vrai composant visuel horizontal color-codé par phase (actuellement liste statique dans `Report.jsx`) |
| **7** | Wazuh (version allégée) | Webhook minimal fonctionnel (déclenche une analyse), HMAC-SHA256 si le temps le permet — priorité réduite suite à la clarification de l'encadrant |
| **7** | Tests | pytest sur les modules critiques (sanitization, scoring, enrichment) |
| **8** | Démo + documentation | Scénarios réels STAR, rapport de stage, slides, soutenance |

**Ne pas envisager** : entraîner un modèle de langage from scratch (irréaliste en 3-4 semaines, dataset insuffisant). Un fine-tuning léger (LoRA) reste une piste "preuve de concept documentée" seulement si le temps le permet en fin de projet, pas un objectif central.

**Ordre de priorité si le temps manque** : bugs IA visibles > sécurité plateforme > évaluation/nouvelles sources RAG > IOC Lookup > Wazuh allégé > ML (piste la plus sacrifiable sans dommage pour le rapport de stage).

---

## 10. Contexte de sécurité à ne jamais oublier

- Le repo a été temporairement mis en public pour transfert vers ce poste — **vérifier qu'il est repassé en privé** (`gh repo edit oumayma-aydi/soc-ai-platform --visibility private`)
- Plusieurs clés API et secrets ont été exposés à un moment (conversation, ancien commit Git) — si une clé semble ancienne/jamais régénérée, considérer une rotation par précaution plutôt que de supposer qu'elle est toujours sûre
- Toujours vérifier avant un push : `git log --all --full-history -- "*.env" "*secret*.yaml"` doit renvoyer vide



```bash
```bash
python -c '
from app.core.database import SessionLocal
from app.models.orm import UserORM
from datetime import datetime, timezone

db = SessionLocal()
try:
    user = db.query(UserORM).filter(UserORM.username == "Admin").first()
    if user:
        user.password_updated_at = datetime.now(timezone.utc)
        user.failed_login_attempts = 0
        db.commit()
        print("OK - date du mot de passe actualisee")
    else:
        print("Utilisateur introuvable")
finally:
    db.close()
'
```
```
