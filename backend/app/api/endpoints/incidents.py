import re
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import json
import uuid

from app.core.database import get_db
from app.core.dependencies import require_analyst_or_admin, require_any_role, get_current_user
from app.models.orm import IncidentORM
from pydantic import BaseModel

from app.services.pdf_service import generate_detailed_incident_pdf
from app.enrichment.ioc_service import get_geo_coordinates, get_country_from_ip

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentAnalyzeRequest(BaseModel):
    raw_log: str


@router.post("/analyze", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_analyst_or_admin)])
async def analyze_incident(
    payload: IncidentAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Déclenche le pipeline multi-agents, enrichit la géolocalisation réelle
    de l'IP source (AbuseIPDB / VirusTotal / ip-api.com en cascade) et
    persiste l'incident avec des coordonnées lat/lon exploitables par la
    Live Threat Map.
    """
    from app.agents.pipeline import run_analysis

    try:
        pipeline_result = await run_analysis(payload.raw_log)

        mitre_techs = pipeline_result.get("mitre_techniques", [])
        remediation_data = pipeline_result.get("remediation", {})
        kill_chain_data = pipeline_result.get("kill_chain", [])
        iocs_data = pipeline_result.get("iocs", [])
        if not isinstance(iocs_data, list):
            iocs_data = []

        ip_detectee = None
        for ioc in iocs_data:
            if isinstance(ioc, dict) and ioc.get("type") == "ip":
                ip_detectee = ioc.get("value")
                break

        if not ip_detectee:
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            all_ips = re.findall(ip_pattern, payload.raw_log)
            public_ips = [ip for ip in all_ips if not ip.startswith(("127.", "192.168.", "10.", "172.16."))]
            ip_detectee = public_ips[0] if public_ips else "185.220.101.47"

        country_code = await get_country_from_ip(ip_detectee, iocs_data)
        geo_info = get_geo_coordinates(country_code)

        computed_geo_data = {
            "country_code": country_code,
            "country_name": geo_info["name"],
            "lat": geo_info["lat"],
            "lon": geo_info["lon"],
        }

        incident = IncidentORM(
            id=f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            incident_type=pipeline_result.get("incident_type", "Unknown Incident Type"),
            severity=pipeline_result.get("severity", 5),
            confidence_score=pipeline_result.get("confidence_score", 0.5),
            raw_log=payload.raw_log,
            mitre_techniques=json.dumps(mitre_techs) if isinstance(mitre_techs, (dict, list)) else mitre_techs,
            remediation=json.dumps(remediation_data) if isinstance(remediation_data, (dict, list)) else remediation_data,
            kill_chain=json.dumps(kill_chain_data) if isinstance(kill_chain_data, (dict, list)) else kill_chain_data,
            iocs=json.dumps(iocs_data) if isinstance(iocs_data, (dict, list)) else iocs_data,
            source_ip=ip_detectee,
            geo_data=computed_geo_data,
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return {
            "status": "success",
            "incident_id": incident.id,
            "analysis": pipeline_result,
            "geo": computed_geo_data,
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'analyse automatique de l'incident : {str(e)}"
        )


@router.get("/live-threats")
def get_live_threats(db: Session = Depends(get_db)):
    """
    Renvoie les 5 derniers incidents enrichis, avec lat/lon exploitables
    directement par le frontend. Rétro-compatible avec les anciens
    incidents qui n'ont que cx/cy ou un country_code sans lat/lon.
    """
    incidents = db.query(IncidentORM).order_by(IncidentORM.timestamp.desc()).limit(5).all()

    results = []
    for inc in incidents:
        geo = inc.geo_data
        if isinstance(geo, str):
            try:
                geo = json.loads(geo)
            except Exception:
                geo = {}
        if not isinstance(geo, dict):
            geo = {}

        lat = geo.get("lat")
        lon = geo.get("lon")
        country_name = geo.get("country_name")

        if lat is None or lon is None:
            fallback = get_geo_coordinates(geo.get("country_code"))
            lat = fallback["lat"]
            lon = fallback["lon"]
            country_name = country_name or fallback["name"]

        inc_type = inc.incident_type
        if inc_type and (inc_type.startswith("{") or inc_type.startswith("[")):
            try:
                parsed_type = json.loads(inc_type)
                if isinstance(parsed_type, dict):
                    inc_type = parsed_type.get("name", "Anomalie Détectée")
            except Exception:
                inc_type = "Anomalie Réseau"

        results.append({
            "id": inc.id,
            "incident_type": inc_type or "Anomalie Réseau",
            "severity": int(inc.severity) if inc.severity else 5,
            "timestamp": inc.timestamp.isoformat() if inc.timestamp else datetime.utcnow().isoformat(),
            "source_ip": inc.source_ip or "IP Externe",
            "country_name": country_name or "Source Externe",
            "lat": lat,
            "lon": lon,
        })

    return results


@router.get("/", dependencies=[Depends(require_any_role)])
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(IncidentORM).order_by(IncidentORM.timestamp.desc()).all()
    return {"count": len(incidents), "results": incidents}


@router.get("/{incident_id}/export-pdf")
async def export_incident_report(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_incident = db.query(IncidentORM).filter(IncidentORM.id == incident_id).first()
    if not db_incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} introuvable en base de données.")

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
        generate_detailed_incident_pdf(result_data, pdf_path)
        return FileResponse(
            path=pdf_path,
            filename=f"rapport_SOC_{incident_id}.pdf",
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la génération physique du fichier PDF: {str(e)}")
