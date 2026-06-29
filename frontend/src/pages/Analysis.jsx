import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Terminal, AlertTriangle, Cpu } from "lucide-react";
import apiClient from "../api/client";

export default function Analysis() {
  const navigate = useNavigate();
  const [logs, setLogs] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

 async function handleAnalyze(e) {
  e.preventDefault();
  if (!logs.trim()) return;
  
  setLoading(true);
  setError("");

  try {
    const token = localStorage.getItem("access_token");

    // Requête ajustée sur l'URL exacte et le schéma Pydantic attendu par ton FastAPI
    const response = await apiClient.post(
      "/api/incidents/analyze", 
      {
        raw_log: logs // ⚡ "raw_log" au singulier, sans le "s" !
      },
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    // Extraction de la clé exacte renvoyée par ton routeur : "incident_id"
    const incidentId = response.data.incident_id;
    
    if (incidentId) {
      navigate(`/report/${incidentId}`);
    } else {
      navigate("/dashboard");
    }
  } catch (err) {
    console.error("Détails de l'erreur d'analyse:", err);
    if (err.response && err.response.data) {
      const serverError = err.response.data.detail || JSON.stringify(err.response.data);
      setError(`Erreur Serveur (${err.response.status}): ${serverError}`);
    } else {
      setError("Le pipeline LangGraph a mis trop de temps à répondre ou le backend est injoignable.");
    }
  } finally {
    setLoading(false);
  }
}

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* En-tête de section corporatif */}
      <div className="text-center space-y-2 py-2">
        <h2 className="text-[#00664F] text-2xl font-black tracking-tight">Nouvelle Analyse AI</h2>
        <p className="text-slate-600 text-sm font-medium">
          Soumission de télémétrie, corrélation RAG (MITRE ATT&CK) et diagnostic automatisé
        </p>
        <div className="w-12 h-1 bg-[#78BE20] mx-auto mt-2 rounded-full"></div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 text-xs font-semibold p-4 rounded-xl flex items-center gap-2">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* BLOC PRINCIPAL DE SOUMISSION - Inspiré du style enveloppe de la newsletter STAR */}
      <div className="bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="bg-[#00664F] p-4 text-white flex items-center gap-3">
          <Terminal size={18} className="text-[#78BE20]" />
          <span className="text-xs font-bold uppercase tracking-wider font-mono">Console d'ingestion de logs</span>
        </div>

        <form onSubmit={handleAnalyze} className="p-6 space-y-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-slate-500 uppercase tracking-wide block">
              Collez les entrées de logs bruts (Syslog, CloudTrail, Auth.log, Nginx...)
            </label>
            <textarea
              value={logs}
              onChange={(e) => setLogs(e.target.value)}
              placeholder="Ex: 2026-06-29T11:05:41Z star-web-server sshd[2415]: Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2"
              className="w-full h-64 bg-slate-50 border border-slate-200 rounded-xl p-4 font-mono text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F] transition-all resize-none"
              disabled={loading}
              required
            />
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={loading || !logs.trim()}
              className="bg-[#00664F] hover:bg-[#004D3C] disabled:bg-slate-300 text-white font-bold text-sm px-6 py-3 rounded-xl transition-all shadow-md flex items-center gap-2"
            >
              <Cpu size={16} className={loading ? "animate-spin" : ""} />
              {loading ? "Calcul du vecteur d'attaque..." : "Lancer l'investigation IA"}
            </button>
          </div>
        </form>
      </div>

      {/* BLOC CONSEILS SÉCURITÉ - Style Cartes Blanches "Nos produits" */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-5 flex gap-4 items-start">
          <div className="p-2.5 bg-emerald-50 text-[#00664F] rounded-lg">
            <ShieldCheck size={20} />
          </div>
          <div>
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wide">Validation RAG intégrée</h4>
            <p className="text-xs text-slate-500 mt-1 leading-relaxed">
              Le moteur compare les structures soumises avec les bases CISA KEV et le framework MITRE ATT&CK en temps réel.
            </p>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5 flex gap-4 items-start">
          <div className="p-2.5 bg-slate-50 text-slate-600 rounded-lg">
            <Terminal size={20} />
          </div>
          <div>
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wide">Anonymisation des Assets</h4>
            <p className="text-xs text-slate-500 mt-1 leading-relaxed">
              Les adresses IP internes et identifiants sensibles de la STAR sont automatiquement corrélés sans fuite externe.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
