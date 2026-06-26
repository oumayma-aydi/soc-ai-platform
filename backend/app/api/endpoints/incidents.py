from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
import json
import uuid

from app.core.database import get_db
from app.core.dependencies import require_analyst_or_admin, require_any_role, get_current_user
from app.models.orm import IncidentORM
from pydantic import BaseModel

from app.services.pdf_service import generate_detailed_incident_pdf

router = APIRouter()

class IncidentAnalyzeRequest(BaseModel):
    raw_log: str

@router.post("/analyze", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_analyst_or_admin)])
async def analyze_incident(
    payload: IncidentAnalyzeRequest, 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Déclenche le pipeline d'analyse multi-agents IA (LangGraph), l'enregistre en base PostgreSQL
    et retourne le rapport complet immédiatement.
    """
    from app.agents.pipeline import run_analysis
    
    try:
        # 1. Appel du pipeline d'agents IA (LangGraph) avec le texte extrait de Pydantic
        pipeline_result = run_analysis(payload.raw_log)
        
        # 2. Sérialisation explicite des objets complexes pour éviter les conflits d'insertion ORM
        mitre_techs = pipeline_result.get("mitre_techniques", [])
        remediation_data = pipeline_result.get("remediation", {})
        kill_chain_data = pipeline_result.get("kill_chain", [])
        iocs_data = pipeline_result.get("iocs", [])

        # 3. Création et persistance dans l'ORM
        incident = IncidentORM(
            id=f"INC-20260622-{uuid.uuid4().hex[:6].upper()}",
            incident_type=pipeline_result.get("incident_type", "Unknown Incident Type"),
            severity=pipeline_result.get("severity", 5),
            confidence_score=pipeline_result.get("confidence_score", 0.5),
            raw_log=payload.raw_log,
            mitre_techniques=json.dumps(mitre_techs) if isinstance(mitre_techs, (dict, list)) else mitre_techs,
            remediation=json.dumps(remediation_data) if isinstance(remediation_data, (dict, list)) else remediation_data,
            kill_chain=json.dumps(kill_chain_data) if isinstance(kill_chain_data, (dict, list)) else kill_chain_data,
            iocs=json.dumps(iocs_data) if isinstance(iocs_data, (dict, list)) else iocs_data
        )
        
        db.add(incident)
        db.commit()
        db.refresh(incident)
        
        # 4. Retourne le résultat complet enrichi de l'ID généré en base de données
        return {
            "status": "success", 
            "incident_id": incident.id, 
            "analysis": pipeline_result
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'analyse automatique de l'incident : {str(e)}"
        )

@router.get("/", dependencies=[Depends(require_any_role)])
def list_incidents(db: Session = Depends(get_db)):
    """
    Récupère l'historique complet des incidents enregistrés au SOC.
    """
    incidents = db.query(IncidentORM).order_by(IncidentORM.timestamp.desc()).all()
    return {"count": len(incidents), "results": incidents}

@router.get("/{incident_id}/export-pdf")
async def export_incident_report(
    incident_id: str, 
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Récupère un incident existant en base et génère son rapport PDF de sécurité hautement détaillé.
    """
    # 1. Chercher l'incident réel dans ta base PostgreSQL
    db_incident = db.query(IncidentORM).filter(IncidentORM.id == incident_id).first()
    
    if not db_incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} introuvable en base de données.")
    
    # 2. Reconstruire le dictionnaire des résultats (Desérialisation propre)
    try:
        result_data = {
            "incident_id": db_incident.id,
            "incident_type": db_incident.incident_type,
            "severity": db_incident.severity,
            "urgency": getattr(db_incident, "urgency", "immediate" if db_incident.severity >= 8 else "medium"),
            "confidence_score": getattr(db_incident, "confidence_score", 0.94),
            "mitre_techniques": json.loads(db_incident.mitre_techniques) if isinstance(db_incident.mitre_techniques, str) else db_incident.mitre_techniques,
            "kill_chain": json.loads(db_incident.kill_chain) if isinstance(db_incident.kill_chain, str) else db_incident.kill_chain,
            "remediation": json.loads(db_incident.remediation) if isinstance(db_incident.remediation, str) else db_incident.remediation,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur de parsing des données de l'incident: {str(e)}")

    pdf_path = f"/tmp/rapport_{incident_id}.pdf"
    
    try:
        # 3. Appel de la fonction du pdf_service
        generate_detailed_incident_pdf(result_data, pdf_path)
        
        return FileResponse(
            path=pdf_path, 
            filename=f"rapport_SOC_{incident_id}.pdf", 
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la génération physique du fichier PDF: {str(e)}")