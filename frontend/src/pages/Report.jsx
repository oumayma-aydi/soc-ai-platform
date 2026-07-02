import { useQuery } from "@tanstack/react-query";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft, FileText, Copy, FileDown,
  Activity, ShieldCheck, Eye, Layers, Key, Clock,
  CheckCircle2, AlertCircle
} from "lucide-react";
import apiClient from "../api/client";
import { getSeverityTier, getUrgencyLabel } from "../utils/severity";

export default function Report() {
  const { id } = useParams();
  const navigate = useNavigate();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["incident", id],
    queryFn: async () => {
      const res = await apiClient.get("/api/incidents/");
      const list = res.data?.results || res.data || [];
      return list.find((item) => item.id === id);
    },
  });

  const handleDownloadPDF = () => {
    const token = localStorage.getItem("access_token");
    window.open(`http://localhost:8000/api/incidents/${id}/export-pdf?token=${token}`, "_blank");
  };

  if (isLoading) {
    return <div className="text-center py-12 font-mono text-xs text-slate-500">Extraction et décodage du rapport d'incident...</div>;
  }

  if (isError || !data) {
    return (
      <div className="bg-[#991B1B]/[0.04] border border-[#991B1B]/20 text-[#991B1B] text-xs font-semibold p-4 rounded-xl max-w-xl mx-auto text-center space-y-3">
        <p>Impossible de localiser l'incident {id} dans le registre.</p>
        <button onClick={() => navigate("/dashboard")} className="text-xs underline block mx-auto">
          Retour au registre
        </button>
      </div>
    );
  }

  // --- PARSING SÉCURISÉ DES CHAMPS JSON ---
  const safeParse = (field) => {
    if (!field) return null;
    if (typeof field === "object") return field;
    try {
      return JSON.parse(field);
    } catch (e) {
      console.warn("Échec du parsing JSON pour le champ:", field, e);
      return null;
    }
  };

  const mitreRaw = safeParse(data.mitre_techniques);
  const mitreTechniques = Array.isArray(mitreRaw) ? mitreRaw : [];

  const remediationData = safeParse(data.remediation) || {};
  const actions = Array.isArray(remediationData.actions) ? remediationData.actions : [];
  const detections = Array.isArray(remediationData.detections_to_deploy) ? remediationData.detections_to_deploy : [];
  const summaryText = remediationData.summary || data.summary || `Anomalie de type "${data.incident_type || "Inconnu"}" détectée par le SOC.`;

  const killChainRaw = safeParse(data.kill_chain);
  const killChain = Array.isArray(killChainRaw) ? killChainRaw : [];

  // Bug corrigé : la condition vérifiait Array.isArray() sur une fonction fléchée
  // au lieu du tableau lui-même, ce qui masquait systématiquement tous les IOCs.
  const iocsRaw = safeParse(data.iocs);
  const iocs = Array.isArray(iocsRaw) ? iocsRaw : [];

  const severity = data.severity || 5;
  const confidence = data.confidence_score ? (data.confidence_score * 100).toFixed(0) : "100";
  const tier = getSeverityTier(severity);

  return (
    <div className="max-w-7xl mx-auto space-y-6 pb-12">

      {/* BARRE D'ACTIONS */}
      <div className="flex justify-between items-center">
        <button
          onClick={() => navigate("/dashboard")}
          className="flex items-center gap-2 text-xs font-bold text-slate-500 hover:text-[#00664F] transition-colors uppercase tracking-wider"
        >
          <ArrowLeft size={14} />
          Retour au registre SOC
        </button>

        <button
          onClick={handleDownloadPDF}
          className="bg-[#00664F] hover:bg-[#004D3C] text-white font-bold text-xs py-2.5 px-4 rounded-xl shadow-sm transition-colors flex items-center gap-2"
        >
          <FileDown size={14} />
          Exporter le PDF Officiel STAR
        </button>
      </div>

      {/* BANDEAU DE STATUT */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`px-2.5 py-1 rounded-md text-[10px] font-black uppercase tracking-wider border ${tier.bg} ${tier.text} ${tier.border}`}>
              Sévérité : {severity}/10
            </span>
            <span className="bg-slate-100 text-slate-600 border border-slate-200 px-2.5 py-1 rounded-md text-[10px] font-mono font-bold">
              ID: {data.id}
            </span>
          </div>
          <h2 className="text-[#00664F] text-xl font-black tracking-tight mt-1">
            {data.incident_type || "Menace Détectée"}
          </h2>
          <p className="text-xs text-slate-500 font-medium">
            Analyse multi-agents achevée avec un indice de confiance cyber de{" "}
            <strong className="text-slate-700 font-bold">{confidence}%</strong>
          </p>
        </div>

        <div className="bg-[#F4F7F6] border border-slate-200 px-4 py-3 rounded-xl min-w-[180px] text-center md:text-right">
          <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Urgence d'intervention</span>
          <span className={`text-sm font-black font-mono block uppercase mt-0.5 ${tier.text}`}>
            {getUrgencyLabel(severity)}
          </span>
        </div>
      </div>

      {/* RÉSUMÉ EXÉCUTIF */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-2">
        <h3 className="text-slate-800 text-xs font-bold uppercase tracking-wider flex items-center gap-2 border-b border-slate-100 pb-2">
          <FileText size={14} className="text-[#00664F]" /> Synthèse de l'Analyse d'Incident
        </h3>
        <p className="text-slate-600 text-xs leading-relaxed font-medium">{summaryText}</p>
      </div>

      {/* GRILLE */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        <div className="lg:col-span-2 space-y-6">

          {/* MITRE ATT&CK */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-4">
            <h3 className="text-slate-800 text-xs font-bold uppercase tracking-wider flex items-center gap-2 border-b border-slate-100 pb-2.5">
              <Layers size={14} className="text-[#00664F]" />
              Matrice des Techniques MITRE ATT&CK Identifiées
            </h3>

            {mitreTechniques.length === 0 ? (
              <p className="text-xs text-slate-400 font-medium">Aucune technique MITRE extraite ou disponible.</p>
            ) : (
              <div className="space-y-3">
                {mitreTechniques.map((tech, index) => (
                  <div key={index} className="border border-slate-100 rounded-xl p-4 bg-slate-50/50">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="bg-[#00664F] text-white text-[10px] font-mono font-bold px-2 py-0.5 rounded">
                          {tech?.id || "T0000"}
                        </span>
                        <h4 className="text-xs font-bold text-slate-800">{tech?.name || "Technique inconnue"}</h4>
                      </div>
                      <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wide bg-white px-2 py-0.5 border border-slate-200 rounded">
                        Tactique : {tech?.tactic || "Non catégorisée"}
                      </span>
                    </div>

                    {tech?.evidence && Array.isArray(tech.evidence) && tech.evidence.length > 0 && (
                      <div className="mt-2.5 pt-2 border-t border-dashed border-slate-200/60">
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Preuves extraites :</span>
                        <ul className="list-disc list-inside space-y-0.5">
                          {tech.evidence.map((ev, i) => (
                            <li key={i} className="text-slate-600 font-mono text-[11px] font-medium pl-1">
                              {ev}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* PLAN DE REMÉDIATION */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-4">
            <h3 className="text-slate-800 text-xs font-bold uppercase tracking-wider flex items-center gap-2 border-b border-slate-100 pb-2.5">
              <ShieldCheck size={14} className="text-[#00664F]" />
              Mesures Correctives & Plan de Remédiation Stratégique
            </h3>

            {actions.length === 0 ? (
              <p className="text-xs text-slate-400 font-medium">Aucun plan d'action immédiat généré.</p>
            ) : (
              <div className="relative border-l border-slate-200 pl-4 ml-2 space-y-6">
                {actions.map((act, index) => {
                  const dot =
                    act?.priority === 1 ? "bg-[#991B1B]" : act?.priority === 2 ? "bg-[#C2410C]" : "bg-[#1E3A8A]";
                  return (
                    <div key={index} className="relative">
                      <span className={`absolute -left-[22px] top-0.5 flex h-3 w-3 items-center justify-center rounded-full ring-4 ring-white ${dot}`} />
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs font-bold text-slate-800">{act?.action || "Action"}</span>
                          <span className="flex items-center gap-1 text-[10px] font-bold text-slate-500 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded font-mono">
                            <Clock size={10} /> {act?.timeframe || "N/A"}
                          </span>
                          {act?.source && (
                            <span className="text-[9px] font-bold text-[#00664F] bg-[#00664F]/[0.05] px-1.5 py-0.5 rounded border border-[#00664F]/15">
                              {act.source}
                            </span>
                          )}
                        </div>
                        <p className="text-slate-500 text-[11px] font-medium leading-relaxed">
                          <strong className="text-slate-600">Procédure :</strong> {act?.how || "Non renseignée"}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {detections.length > 0 && (
              <div className="mt-4 pt-4 border-t border-slate-100 space-y-2">
                <span className="text-[10px] font-black text-slate-400 uppercase tracking-wider block">Signatures SIEM conseillées</span>
                <div className="flex flex-wrap gap-2">
                  {detections.map((det, idx) => (
                    <span key={idx} className="bg-slate-100 text-slate-700 border border-slate-200 text-[11px] font-medium px-2.5 py-1 rounded-lg">
                      {det}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* COLONNE DE DROITE */}
        <div className="space-y-6">

          {/* CYBER KILL CHAIN */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-3">
            <h3 className="text-slate-800 text-xs font-bold uppercase tracking-wider flex items-center gap-2 border-b border-slate-100 pb-2">
              <Activity size={14} className="text-[#00664F]" /> Progression Kill Chain
            </h3>
            {killChain.length === 0 ? (
              <div className="space-y-2.5 text-[11px] font-medium">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 font-bold text-[#00664F]">
                    <CheckCircle2 size={12} /> Phase 1 : Ingestion
                  </span>
                  <span className="text-slate-400">Achevé</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 font-bold text-[#C2410C]">
                    <Activity size={12} /> Phase 2 : Analyse agents
                  </span>
                  <span className="text-slate-400">En cours</span>
                </div>
                <div className="flex items-center justify-between text-slate-300">
                  <span className="flex items-center gap-1.5 font-bold">
                    <Clock size={12} /> Phase 3 : Exfiltration
                  </span>
                  <span>Non détecté</span>
                </div>
              </div>
            ) : (
              <div className="space-y-2 font-mono text-[11px]">
                {killChain.map((step, idx) => (
                  <div key={idx} className="flex justify-between border-b border-slate-50 pb-1">
                    <span className="text-slate-700 font-bold">{step?.phase || "Phase"}</span>
                    <span className="text-[#00664F]">{step?.status || "Actif"}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* IOCS */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-3">
            <h3 className="text-slate-800 text-xs font-bold uppercase tracking-wider flex items-center gap-2 border-b border-slate-100 pb-2">
              <Key size={14} className="text-[#00664F]" /> Renseignement IoC & Artefacts
            </h3>
            {iocs.length === 0 ? (
              <div className="p-2 bg-slate-50 border border-slate-100 rounded-xl">
                <span className="text-[10px] text-slate-400 font-bold uppercase block">Analyse IoC</span>
                <span className="text-xs font-mono font-bold text-slate-700">Aucun indicateur explicite extrait</span>
              </div>
            ) : (
              <div className="space-y-2">
                {iocs.map((ioc, idx) => (
                  <div key={idx} className="p-2 bg-slate-50 border border-slate-100 rounded-xl">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">{ioc?.type || "Indicateur"}</span>
                    <span className="text-xs font-mono font-bold text-slate-700 break-all">{ioc?.value || JSON.stringify(ioc)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* LOG BRUT SOURCE */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <h3 className="text-slate-800 text-xs font-bold uppercase tracking-wider flex items-center gap-2">
                <Eye size={14} className="text-slate-500" /> Source de l'Événement
              </h3>
              <button
                onClick={() => navigator.clipboard.writeText(data.raw_log || "")}
                className="text-slate-400 hover:text-[#00664F] transition-colors"
              >
                <Copy size={13} />
              </button>
            </div>

            <div className="bg-slate-50 border border-slate-200 text-slate-700 font-mono text-[10px] p-3 rounded-xl overflow-y-auto max-h-64 whitespace-pre-wrap leading-relaxed">
              {data.raw_log || "Aucun log brut associé."}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
