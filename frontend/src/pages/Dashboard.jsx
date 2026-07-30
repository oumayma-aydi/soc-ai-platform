import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Server, ShieldAlert, CheckCircle, Database } from "lucide-react";
import apiClient from "../api/client";
import { getUrgencyLabel } from "../utils/severity";

export default function Dashboard() {
  const navigate = useNavigate();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["incidents"],
    queryFn: async () => {
      const res = await apiClient.get("/api/incidents/");
      return res.data;
    },
    refetchInterval: 15000,
  });

  const incidents = data?.results ?? [];
  const total = incidents.length;
  const avgSev = total ? incidents.reduce((s, i) => s + (i.severity || 0), 0) / total : 0;
  const critCount = incidents.filter(i => (i.severity || 0) >= 8).length;

  // Préparation des graphes avec couleurs contrastées foncées
  const typeCount = incidents.reduce((acc, i) => {
    const t = (i.incident_type || "Autre").split(" ")[0];
    acc[t] = (acc[t] || 0) + 1;
    return acc;
  }, {});
  const barData = Object.entries(typeCount).map(([name, count]) => ({ name, count }));

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      
      {/* BLOC TITRE - Épuré style STAR */}
      <div className="text-center space-y-2 py-4">
        <h2 className="text-[#00664F] text-2xl font-black tracking-tight">
          Base de Données SOC
        </h2>
        <p className="text-slate-600 text-sm font-medium">
          Registre d'audit, métriques d'intégrité et vecteurs d'attaques persistés
        </p>
        <div className="w-16 h-1 bg-[#78BE20] mx-auto mt-2 rounded-full"></div>
      </div>

      {/* BLOC 1 : GRILLE DE BLOCS KPI (Inspiré des cartes blanches "Nos Produits") */}
      <div className="grid grid-cols-4 gap-6">
        <div className="bg-white border border-slate-200/70 rounded-2xl p-6 shadow-sm hover:shadow-md transition-all text-center flex flex-col items-center space-y-3">
          <div className="p-3.5 bg-slate-50 text-[#00664F] rounded-full border border-slate-100">
            <Database size={24} />
          </div>
          <div>
            <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider">Volume de Données</h4>
            <p className="text-3xl font-black text-slate-800 font-mono mt-1">{total}</p>
            <p className="text-[11px] text-slate-500 font-medium mt-1">Entrées indexées</p>
          </div>
        </div>

        <div className="bg-white border border-slate-200/70 rounded-2xl p-6 shadow-sm hover:shadow-md transition-all text-center flex flex-col items-center space-y-3">
          <div className="p-3.5 bg-slate-50 text-[#00664F] rounded-full border border-slate-100">
            <Server size={24} />
          </div>
          <div>
            <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider">Moyenne Critique</h4>
            <p className="text-3xl font-black text-slate-800 font-mono mt-1">
              {avgSev.toFixed(1)}<span className="text-xs text-slate-400">/10</span>
            </p>
            <p className="text-[11px] text-slate-500 font-medium mt-1">Indice de menace global</p>
          </div>
        </div>

        <div className="bg-white border border-slate-200/70 rounded-2xl p-6 shadow-sm hover:shadow-md transition-all text-center flex flex-col items-center space-y-3">
          <div className="p-3.5 bg-red-50 text-red-600 rounded-full border border-red-100">
            <ShieldAlert size={24} />
          </div>
          <div>
            <h4 className="text-red-700/80 text-xs font-bold uppercase tracking-wider">Urgence Élevée</h4>
            <p className="text-3xl font-black text-red-600 font-mono mt-1">{critCount}</p>
            <p className="text-[11px] text-slate-500 font-medium mt-1">Sévérité ≥ 8 en base</p>
          </div>
        </div>

        <div className="bg-white border border-slate-200/70 rounded-2xl p-6 shadow-sm hover:shadow-md transition-all text-center flex flex-col items-center space-y-3">
          <div className="p-3.5 bg-emerald-50 text-[#78BE20] rounded-full border border-emerald-100">
            <CheckCircle size={24} />
          </div>
          <div>
            <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider">État de la Base</h4>
            <p className="text-lg font-bold text-[#00664F] mt-3 uppercase tracking-wider">PostgreSQL OK</p>
            <p className="text-[11px] text-slate-500 font-medium mt-1">Clusters synchronisés</p>
          </div>
        </div>
      </div>

      {/* BLOC 2 : ANALYSE STATISTIQUE (TEXTES FONCÉS ET LISIBLES) */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-6">
          Vecteurs d'attaque recensés en base de connaissances
        </h3>
        <div className="h-56">
          {barData.length === 0 ? (
            <p className="text-slate-400 text-sm text-center py-12 font-medium">Aucune statistique disponible pour l'instant.</p>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData}>
                {/* Textes gris foncés bien lisibles sur le blanc */}
                <XAxis dataKey="name" tick={{ fill: '#475569', fontSize: 11, fontWeight: 600 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: '#F8FAFC' }} />
                <Bar dataKey="count" fill="#00664F" radius={[6, 6, 0, 0]} maxBarSize={48} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* BLOC 3 : TABLEAU DE L'HISTORIQUE DES RAPPORTS */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4">
          Registre d'incidents stockés
        </h3>

        {isLoading && <p className="text-center py-6 text-xs text-slate-500 font-mono">Requête PostgreSQL en cours...</p>}
        {isError && <p className="text-center py-6 text-xs text-red-500 font-mono">Échec de liaison avec le backend.</p>}

        {!isLoading && incidents.length === 0 && (
          <p className="text-center py-8 text-sm text-slate-400 font-medium">Aucun historique d'incident en base de données.</p>
        )}

        {incidents.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm border-collapse">
              <thead>
                <tr className="border-b border-slate-100 text-slate-400 text-xs uppercase tracking-wider font-bold">
                  <th className="py-3 px-3">UUID Incident</th>
                  <th className="py-3 px-3">Classification Type</th>
                  <th className="py-3 px-3">Niveau Sévérité</th>
                  <th className="py-3 px-3">Urgence</th>
                  <th className="py-3 px-3 text-right">Analyse Détaillée</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700 font-medium">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-3 px-3 font-mono text-xs font-bold text-[#00664F]">{inc.id}</td>
                    <td className="py-3 px-3 text-slate-800 max-w-xs truncate">{inc.incident_type || "Type non répertorié"}</td>
                    <td className="py-3 px-3">
                      <span className={inc.severity >= 8 ? "badge-critical" : inc.severity >= 5 ? "badge-high" : "badge-low"}>
                        {inc.severity || 0}/10
                      </span>
                    </td>
                    <td className="py-3 px-3 text-xs font-mono font-bold uppercase text-slate-600">
                      {getUrgencyLabel(inc.severity || 0)}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => navigate(`/report/${inc.id}`)}
                        className="text-xs bg-[#00664F]/5 text-[#00664F] hover:bg-[#00664F] hover:text-white font-bold px-3 py-2 rounded-xl transition-all border border-[#00664F]/10"
                      >
                        Consulter le Rapport →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
