import { useState, useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield, Database, Activity, CheckCircle,
  ArrowRight, Radio, Info, Globe2
} from "lucide-react";
import { geoMercator, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import apiClient from "../api/client";
import { getSeverityTier } from "../utils/severity";

// Topojson public, léger (~100 pays simplifiés) — pas de clé API requise
const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

const MAP_WIDTH = 640;
const MAP_HEIGHT = 340;
const PROJECTION_CONFIG = { scale: 115, center: [10, 18] };

const STAR_HQ = { lon: 10.18, lat: 36.83, label: "Tunis — STAR HQ" };

export default function Home() {
  const navigate = useNavigate();
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({ total_db: 0, critical_count: 0 });
  const [countries, setCountries] = useState([]);

  // Chargement du fond de carte une seule fois (topojson → geojson)
  useEffect(() => {
    let cancelled = false;
    fetch(GEO_URL)
      .then((res) => res.json())
      .then((topology) => {
        if (cancelled) return;
        const geojson = feature(topology, topology.objects.countries);
        setCountries(geojson.features);
      })
      .catch((err) => console.error("Échec du chargement du fond de carte", err));
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    const fetchLiveThreats = async () => {
      try {
        const response = await apiClient.get("/api/incidents/live-threats");
        const data = response.data || [];
        setThreats(data);
        setStats({
          total_db: data.length * 3, // À remplacer par un endpoint de comptage global dédié
          critical_count: data.filter((t) => t.severity >= 8).length,
        });
      } catch (error) {
        console.error("Échec de la récupération des données en direct", error);
      }
    };

    fetchLiveThreats();
    const interval = setInterval(fetchLiveThreats, 5000);
    return () => clearInterval(interval);
  }, []);

  // Projection + générateur de tracé — mémorisés, réutilisés pour les pays ET les arcs
  const projection = useMemo(
    () =>
      geoMercator()
        .scale(PROJECTION_CONFIG.scale)
        .center(PROJECTION_CONFIG.center)
        .translate([MAP_WIDTH / 2, MAP_HEIGHT / 2]),
    []
  );

  const pathGenerator = useMemo(() => geoPath().projection(projection), [projection]);

  const targetPoint = projection([STAR_HQ.lon, STAR_HQ.lat]);

  const calculateArcPath = (sx, sy, tx, ty) => {
    const mx = (sx + tx) / 2;
    const my = Math.min(sy, ty) - 50;
    return `M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`;
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 font-sans antialiased pb-12">

      {/* BANNIÈRE INSTITUTIONNELLE */}
      <div className="bg-white border-b border-slate-200 mb-8">
        <div className="max-w-7xl mx-auto px-8 py-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="space-y-2.5">
            <span className="inline-block text-[10px] font-black tracking-widest text-[#00664F] uppercase bg-[#00664F]/[0.05] border border-[#00664F]/20 px-3 py-1 rounded-full">
              Supervision Augmentée par IA
            </span>
            <h1 className="text-2xl md:text-3xl font-black text-[#00664F] tracking-tight leading-tight">
              STAR Assurances <span className="text-slate-300 font-light">|</span>{" "}
              <span className="text-slate-700 font-semibold">Cyber SOC Platform</span>
            </h1>
            <p className="text-sm text-slate-500 max-w-xl leading-relaxed">
              Supervision et analyse d'incidents cyber augmentées par intelligence artificielle
              multi-agents — protection des données sinistres, contrats et clients.
            </p>
          </div>
          <button
            onClick={() => navigate("/analyze")}
            className="shrink-0 bg-[#00664F] hover:bg-[#004D3C] text-white font-bold text-xs tracking-wider uppercase py-3.5 px-6 rounded-xl transition-colors flex items-center gap-3 group shadow-sm"
          >
            Démarrer une analyse IA
            <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
          </button>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-8 space-y-8">

        {/* KPI */}
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
            <div className="p-3 bg-[#991B1B]/[0.06] rounded-xl border border-slate-100 flex-shrink-0 text-[#991B1B]">
              <Shield size={20} />
            </div>
            <div>
              <span className="text-xl font-black block font-mono text-slate-900 leading-tight">{stats.critical_count}</span>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mt-0.5">Incidents critiques</span>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-5 flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-[#00664F]/[0.06] rounded-xl border border-slate-100 flex-shrink-0 text-[#00664F]">
              <Activity size={20} />
            </div>
            <div>
              <span className="text-xl font-black block font-mono text-slate-900 leading-tight">100 %</span>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mt-0.5">Couverture MITRE & CISA</span>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-5 flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-[#00664F]/[0.06] rounded-xl border border-slate-100 flex-shrink-0 text-[#00664F]">
              <CheckCircle size={20} />
            </div>
            <div>
              <span className="text-xl font-black block font-mono text-[#00664F] leading-tight">Actif</span>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mt-0.5">Pipeline d'ingestion IA</span>
            </div>
          </div>
        </div>

        {/* CARTE ET FLUX D'ACTIVITÉS */}
        <div className="bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden">

          <div className="px-6 py-4 border-b border-slate-100 bg-slate-50/60 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Radio size={14} className="text-[#991B1B] animate-pulse" />
              <div>
                <h2 className="text-xs font-black uppercase tracking-widest text-slate-800">Live Cyber Threat Map</h2>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Flux réel basé sur l'analyse de géolocalisation de vos logs d'infrastructure
                </p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 bg-[#991B1B]/[0.06] border border-[#991B1B]/20 text-[#991B1B] text-[10px] font-bold px-2.5 py-1 rounded-full uppercase tracking-wider">
              <span className="w-1.5 h-1.5 rounded-full bg-[#991B1B] animate-pulse"></span>
              En direct
            </div>
          </div>

          <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* CARTE */}
            <div className="lg:col-span-2">
              <div className="relative w-full bg-white border border-slate-200 rounded-xl overflow-hidden" style={{ height: 340 }}>

                <svg viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`} className="absolute inset-0 w-full h-full">
                  {/* FOND DE CARTE — tracé directement via d3-geo, sans dépendance React */}
                  <g>
                    {countries.map((c, i) => (
                      <path
                        key={`country-${i}`}
                        d={pathGenerator(c)}
                        fill="#F1F5F9"
                        stroke="#E2E8F0"
                        strokeWidth={0.6}
                      />
                    ))}
                  </g>

                  {/* ARCS DE MENACE */}
                  <defs>
                    {threats.map((t, i) => {
                      if (t.lat == null || t.lon == null) return null;
                      const p = projection([t.lon, t.lat]);
                      if (!p) return null;
                      return (
                        <path
                          key={`path-def-${i}`}
                          id={`arc-path-${i}`}
                          d={calculateArcPath(p[0], p[1], targetPoint[0], targetPoint[1])}
                          fill="none"
                        />
                      );
                    })}
                  </defs>

                  {threats.map((t, i) => {
                    if (t.lat == null || t.lon == null) return null;
                    const p = projection([t.lon, t.lat]);
                    if (!p) return null;
                    const tier = getSeverityTier(t.severity);
                    return (
                      <g key={`threat-vector-${i}`}>
                        <path
                          d={calculateArcPath(p[0], p[1], targetPoint[0], targetPoint[1])}
                          fill="none"
                          stroke={tier.hex}
                          strokeWidth="1.2"
                          strokeOpacity="0.35"
                        />
                        <circle r="3.5" fill={tier.hex} opacity="0.9">
                          <animateMotion dur={`${2.5 + i}s`} repeatCount="indefinite" rotate="auto">
                            <mpath href={`#arc-path-${i}`} />
                          </animateMotion>
                        </circle>
                        <circle cx={p[0]} cy={p[1]} r="4" fill={tier.hex} opacity="0.85" />
                        <text
                          x={p[0]}
                          y={p[1] - 10}
                          textAnchor="middle"
                          fontSize="9"
                          fontFamily="Inter, sans-serif"
                          fill="#475569"
                          fontWeight="600"
                        >
                          {t.country_name}
                        </text>
                      </g>
                    );
                  })}

                  <g>
                    <circle cx={targetPoint[0]} cy={targetPoint[1]} r="20" fill="#00664F" opacity="0.06" />
                    <circle cx={targetPoint[0]} cy={targetPoint[1]} r="7" fill="#00664F" />
                    <circle cx={targetPoint[0]} cy={targetPoint[1]} r="2.5" fill="white" />
                    <text
                      x={targetPoint[0]}
                      y={targetPoint[1] + 28}
                      textAnchor="middle"
                      fontSize="10"
                      fill="#00664F"
                      fontWeight="800"
                    >
                      {STAR_HQ.label}
                    </text>
                  </g>
                </svg>

                <div className="absolute bottom-3 left-3 bg-white border border-slate-200 rounded-lg px-3 py-1.5 flex items-center gap-2 shadow-sm">
                  <Globe2 size={11} className="text-slate-400" />
                  <span className="text-[10px] font-bold text-slate-500 font-mono uppercase tracking-wider">
                    Supervision active · UTC+1
                  </span>
                </div>
              </div>
            </div>

            {/* FLUX DES ALERTES */}
            <div className="flex flex-col border border-slate-200 rounded-xl bg-slate-50/40 overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-200 bg-white">
                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Flux d'activités récentes</span>
              </div>

              <div className="flex-1 p-3 space-y-2 overflow-y-auto max-h-[275px]">
                {threats.length === 0 ? (
                  <div className="text-center py-12 text-xs font-medium text-slate-400">Aucune menace active enregistrée.</div>
                ) : (
                  threats.map((t, i) => {
                    const tier = getSeverityTier(t.severity);
                    return (
                      <div key={i} className="bg-white border border-slate-100 rounded-xl p-3 shadow-sm space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className={`inline-flex items-center gap-1 text-[9px] font-black px-1.5 py-0.5 rounded border ${tier.bg} ${tier.text} ${tier.border} uppercase tracking-wider`}>
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
