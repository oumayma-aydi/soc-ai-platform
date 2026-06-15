import re
import base64
import unicodedata
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
from datetime import datetime

# ==========================================
# 1. SOUS-MODÈLES STRUCTURÉS
# ==========================================

class IOC(BaseModel):
    type: str = Field(..., description="Type d'IOC: ip, email, domain, hash")
    value: str = Field(..., description="La valeur brute de l'indicateur")
    source: Optional[str] = Field(None)

class MitreTechnique(BaseModel):
    id: str = Field(..., examples=["T1566.001"])
    name: str = Field(...)
    tactic: str = Field(...)
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)

class RemediationAction(BaseModel):
    priority: int = Field(..., ge=1, le=5)
    timeframe: str = Field(...)
    action: str = Field(...)
    how: str = Field(...)
    source: str = Field(...)

# ==========================================
# 2. MODÈLE PRINCIPAL
# ==========================================

class Incident(BaseModel):
    """
    Représente un incident SOC complet.
    Sert à valider l'entrée (raw_log) et à structurer le rapport final.
    """
    id: Optional[str] = Field(None, description="Identifiant unique de l'incident (ex: INC-2026-001)")
    
    # --- DONNÉES ENTRANTES (Input Validation Strict) ---
    raw_log: str = Field(
        ..., 
        min_length=15, 
        max_length=50000, 
        description="Le log brut provenant du SIEM ou de l'analyste"
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Date de détection")

    # --- DONNÉES ENRICHIES ET ENRICHISEMENT MULTI-AGENTS (Output Validation) ---
    iocs: List[IOC] = Field(default_factory=list)
    incident_type: Optional[str] = Field(None, description="Classification (ex: Phishing, Brute Force)")
    severity: Optional[int] = Field(None, ge=1, le=10, description="Score de sévérité de 1 à 10")
    urgency: Optional[str] = Field(None, description="Niveau d'urgence (immediate, high, medium, low)")
    triage_evidence: List[str] = Field(default_factory=list)
    
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    kill_chain: List[Dict[str, Any]] = Field(default_factory=list)
    kill_chain_narrative: Optional[str] = None
    
    remediation: Optional[Dict[str, Any]] = Field(None, description="Bloc remédiation complet")
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Score de confiance déterministe")

    # ==========================================
    # 3. VALIDATEURS PERSONNALISÉS (Business Logic)
    # ==========================================

    @field_validator('raw_log')
    @classmethod
    def validate_and_sanitize_input(cls, log_content: str) -> str:
        """
        Validateur multicouche de production : Décode le vrai Base64 (y compris avec padding =),
        normalise l'Unicode, bloque les injections HTML/XML et détecte les jailbreaks.
        """
        current_text = log_content.strip()

        # 1. DÉCODAGE BASE64 AMÉLIORÉ
        # Cette regex capture les blocs denses de base64 de min 8 caractères, avec ou sans padding '=' à la fin
        base64_pattern = r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        
        def decode_base64(match):
            candidate = match.group(0)
            # Éviter de traiter des mots isolés trop courts du dictionnaire
            if len(candidate) < 12:
                return candidate
            try:
                # Vérification stricte du décodage
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                
                # Si le résultat contient des mots lisibles (alphanumériques), on valide la traduction
                if any(c.isalnum() for c in decoded_str):
                    return decoded_str
            except Exception:
                pass
            return match.group(0)
            
        current_text = re.sub(base64_pattern, decode_base64, current_text)

        # 2. NORMALISATION UNICODE
        current_text = unicodedata.normalize('NFKC', current_text)

        # 3. ANALYSE ET NETTOYAGE XML / HTML
        log_lower_raw = current_text.lower()
        
        if re.search(r'<(script|html|iframe|object|embed|bypass|style)>', log_lower_raw):
            raise ValueError("Sécurité : Balises HTML/XML hostiles détectées dans le log.")

        text_normalized_tags = re.sub(r'<[^>]*>', ' ', current_text)

        # 4. DÉTECTION DES MOTS-CLÉS DE JAILBREAK
        jailbreak_keywords = [
            "ignore previous instructions", 
            "ignore all instructions", 
            "you are no longer a soc analyst",
            "system prompt bypass",
            "override system prompt",
            "ignore rules"
        ]
        
        log_lower_clean = text_normalized_tags.lower()
        for keyword in jailbreak_keywords:
            if keyword in log_lower_raw or keyword in log_lower_clean:
                raise ValueError("Sécurité : Tentative d'injection de prompt ou de jailbreak détectée (Filtre Multicouche).")

        return text_normalized_tags.strip()

# Reconstruction des modèles liés de Pydantic v2
Incident.model_rebuild()