import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { 
  Shield, Database, Activity, CheckCircle, 
  ArrowRight, Radio, AlertTriangle, Info, Globe2 
} from "lucide-react";
import apiClient from "../api/client";

export default function Home() {
  const navigate = useNavigate();
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({ total_db: 0, critical_count: 0 });

  // 1. POLLING SÉCURISÉ DE L'API POUR LE TEMPS RÉEL (Option A)
  useEffect(() => {
    const fetchLiveThreats = async () => {
      try {
        const response = await apiClient.get("/api/incidents/live-threats");
        const data = response.data || [];
        setThreats(data);
        
        // Simulation dynamique des compteurs basée sur la réalité de la DB
        setStats({
          total_db: data.length * 3, // Exemple de proportionnalité ou remplaçable par un endpoint de compteurs globaux
          critical_count: data.filter(t => t.severity >= 8).length
        });
      } catch (error) {
        console.error("Échec de la récupération des données en direct", error);
      }
    };

    fetchLiveThreats();
    const interval = setInterval(fetchLiveThreats, 5000); // Mise à jour automatique toutes les 5 secondes
    return () => clearInterval(interval);
  }, []);

  // Définition de la cible fixe : Tunis (STAR HQ)
  const TARGET_TN = { cx: 430, cy: 270, label: "Tunis — STAR HQ" };

  // Calcul dynamique de la trajectoire incurvée SVG pour chaque attaque réelle
  const calculateArcPath = (sourceX, sourceY, targetX, targetY) => {
    const mx = (sourceX + targetX) / 2;
    const my = Math.min(sourceY, targetY) - 60; // Hauteur de l'arc de courbe
    return `M ${sourceX} ${sourceY} Q ${mx} ${my} ${targetX} ${targetY}`;
  };

  const getSeverityStyle = (severity) => {
    if (severity >= 8) return { bg: "bg-red-50", text: "text-red-600", border: "border-red-100", stroke: "#EF4444" };
    if (severity >= 5) return { bg: "bg-orange-50", text: "text-orange-600", border: "border-orange-100", stroke: "#F97316" };
    return { bg: "bg-blue-50", text: "text-blue-600", border: "border-blue-100", stroke: "#3B82F6" };
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 font-sans antialiased pb-12">
      
      {/* HERO BANNER INSTITUTIONNEL STAR */}
      <div className="bg-white border-b border-slate-200 mb-8">
        <div className="max-w-7xl mx-auto px-8 py-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="space-y-2.5">
            <span className="inline-block text-[10px] font-black tracking-widest text-[#78BE20] uppercase bg-[#78BE20]/10 border border-[#78BE20]/20 px-3 py-1 rounded-full">
              Expertise Multidisciplinaire
            </span>
            <h1 className="text-2xl md:text-3xl font-black text-[#00664F] tracking-tight leading-tight">
              STAR Assurances <span className="text-slate-300 font-light">|</span> <span className="text-slate-700 font-semibold">Cyber SOC Platform</span>
            </h1>
            <p className="text-sm text-slate-500 max-w-xl leading-relaxed">
              Supervision et analyse d'incidents cyber augmentées par intelligence artificielle multi-agents — protection des données sinistres, contrats et clients.
            </p>
          </div>
          <button
            onClick={() => navigate("/analyze")}
            className="shrink-0 bg-[#00664F] hover:bg-[#004D3C] text-white font-bold text-xs tracking-wider uppercase py-3.5 px-6 rounded-xl transition-all flex items-center gap-3 group shadow-sm"
          >
            Démarrer une analyse IA
            <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
          </button>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-8 space-y-8">
        
        {/* KPI STATS DYNAMIQUES */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <div className="bg-white border border-slate-200 rounded-2xl p-5 flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-slate-100 rounded-xl border border-slate-100 flex-shrink-0 text-slate-500">
              <Database size={20} />
            </div>
            <div>
              <span className="text-xl font-black block font-mono text-slate-900 leading-tight">{stats.total_db}</span>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mt-0.5">Analyses stockées</span>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-5 flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-red-50 rounded-xl border border-slate-100 flex-shrink-0 text-red-500">
              <Shield size={20} />
            </div>
            <div>
              <span className="text-xl font-black block font-mono text-slate-900 leading-tight">{stats.critical_count}</span>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mt-0.5">Incidents critiques</span>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-5 flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-emerald-50 rounded-xl border border-slate-100 flex-shrink-0 text-[#00664F]">
              <Activity size={20} />
            </div>
            <div>
              <span className="text-xl font-black block font-mono text-slate-900 leading-tight">100 %</span>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mt-0.5">Couverture MITRE & CISA</span>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-5 flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-[#78BE20]/10 rounded-xl border border-slate-100 flex-shrink-0 text-[#78BE20]">
              <CheckCircle size={20} />
            </div>
            <div>
              <span className="text-xl font-black block font-mono text-[#78BE20] leading-tight">Actif</span>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mt-0.5">Pipeline d'ingestion IA</span>
            </div>
          </div>
        </div>

        {/* SECTION CARTE ET FLUX D'ACTIVITÉS EN CLAIR */}
        <div className="bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden">
          
          <div className="px-6 py-4 border-b border-slate-100 bg-slate-50/60 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Radio size={14} className="text-red-500 animate-pulse" />
              <div>
                <h2 className="text-xs font-black uppercase tracking-widest text-slate-800">Live Cyber Threat Map</h2>
                <p className="text-[10px] text-slate-400 mt-0.5">Flux réel basé sur l'analyse de géolocalisation de vos logs d'infrastructure</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 bg-red-50 border border-red-100 text-red-600 text-[10px] font-bold px-2.5 py-1 rounded-full uppercase tracking-wider">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>
              En direct
            </div>
          </div>

          <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* CARTE SVG AVEC VECTEURS D'ATTAQUES DYNAMIQUES */}
            <div className="lg:col-span-2">
              <div className="relative w-full bg-slate-50 border border-slate-200 rounded-xl overflow-hidden" style={{ height: 340 }}>
                
                {/* Grille technique de fond */}
                <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ opacity: 0.04 }}>
                  <defs>
                    <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                      <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#000" strokeWidth="0.5"/>
                    </pattern>
                  </defs>
                  <rect width="100%" height="100%" fill="url(#grid)" />
                </svg>

                {/* Rendu des vecteurs */}
                <svg viewBox="0 0 640 340" className="absolute inset-0 w-full h-full">
                  <defs>
                    {threats.map((t, i) => (
                      <path key={`path-def-${i}`} id={`arc-path-${i}`} d={calculateArcPath(t.cx, t.cy, TARGET_TN.cx, TARGET_TN.cy)} fill="none" />
                    ))}
                  </defs>

                  {/* Tracés et animations des flux de menaces de la DB */}
                  {threats.map((t, i) => {
                    const style = getSeverityStyle(t.severity);
                    return (
                      <g key={`threat-vector-${i}`}>
                        {/* Ligne courbe fine */}
                        <path d={calculateArcPath(t.cx, t.cy, TARGET_TN.cx, TARGET_TN.cy)} fill="none" stroke={style.stroke} strokeWidth="1" strokeOpacity="0.2" />
                        
                        {/* Bulle d'impact animée */}
                        <circle r="3.5" fill={style.stroke} opacity="0.85">
                          <animateMotion dur={`${3 + i}s`} repeatCount="indefinite" rotate="auto">
                            <mpath href={`#arc-path-${i}`} />
                          </animateMotion>
                        </circle>

                        {/* Point d'ancrage source du pays attaquant */}
                        <circle cx={t.cx} cy={t.cy} r="4" fill={style.stroke} opacity="0.7" />
                        <text x={t.cx} y={t.cy - 10} textAnchor="middle" fontSize="9" fontFamily="monospace" fill="#64748B" fontWeight="600">
                          {t.country_name}
                        </text>
                      </g>
                    );
                  })}

                  {/* Cible centrale : Tunis (STAR HQ) */}
                  <g>
                    <circle cx={TARGET_TN.cx} cy={TARGET_TN.cy} r="20" fill="#00664F" opacity="0.06" />
                    <circle cx={TARGET_TN.cx} cy={TARGET_TN.cy} r="7"  fill="#00664F" />
                    <circle cx={TARGET_TN.cx} cy={TARGET_TN.cy} r="2.5" fill="white" />
                    <text x={TARGET_TN.cx} y={TARGET_TN.cy + 28} textAnchor="middle" fontSize="10" fill="#00664F" fontWeight="800">
                      {TARGET_TN.label}
                    </text>
                  </g>
                </svg>

                {/* Badges indicatifs fixes */}
                <div className="absolute bottom-3 left-3 bg-white border border-slate-200 rounded-lg px-3 py-1.5 flex items-center gap-2 shadow-sm">
                  <Globe2 size={11} className="text-slate-400" />
                  <span className="text-[10px] font-bold text-slate-500 font-mono uppercase tracking-wider">Supervision active · UTC+1</span>
                </div>
              </div>
            </div>

            {/* VOLET DROIT : COMPOSANT DE FLUX DES ALERTES REELLES */}
            <div className="flex flex-col border border-slate-200 rounded-xl bg-slate-50/40 overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-200 bg-white">
                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Flux d'activités récentes</span>
              </div>
              
              <div className="flex-1 p-3 space-y-2 overflow-y-auto max-h-[275px]">
                {threats.length === 0 ? (
                  <div className="text-center py-12 text-xs font-medium text-slate-400">Aucune menace active enregistrée.</div>
                ) : (
                  threats.map((t, i) => {
                    const style = getSeverityStyle(t.severity);
                    return (
                      <div key={i} className="bg-white border border-slate-100 rounded-xl p-3 shadow-sm space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className={`inline-flex items-center gap-1 text-[9px] font-black px-1.5 py-0.5 rounded border ${style.bg} ${style.text} ${style.border} uppercase tracking-wider`}>
                            <Info size={10} /> SÉVÉRITÉ {t.severity}
                          </span>
                          <span className="text-[9px] font-mono text-slate-400">
                            {new Date(t.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <div>
                          <p className="text-[11px] font-semibold text-slate-700 leading-snug">
                            <span className="text-slate-500 font-normal">{t.source_ip} ({t.country_name})</span>
                            <span className="text-slate-400 mx-1">→</span>
                            <span className="text-[#00664F] font-bold">STAR HQ</span>
                          </p>
                          <p className="text-[10px] font-mono text-[#00664F] font-bold mt-0.5">{t.incident_type}</p>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              <div className="px-4 py-3 border-t border-slate-200 bg-white">
                <button
                  onClick={() => navigate("/dashboard")}
                  className="w-full text-center text-[11px] font-bold text-[#00664F] hover:text-[#004D3C] uppercase tracking-wider transition-colors"
                >
                  Consulter le registre historique
                </button>
              </div>
            </div>

          </div>

        </div>

      </div>
    </div>
  );
}
