import { NavLink, useNavigate } from "react-router-dom";
import { LayoutDashboard, Search, LogOut, Shield, Globe, Users } from "lucide-react";

const nav = [
  { to: "/",          icon: Globe,           label: "Accueil & Threat Map" },
  { to: "/dashboard", icon: LayoutDashboard, label: "Base de Données SOC" },
  { to: "/analysis",  icon: Search,          label: "Nouvelle Analyse AI"  },
];

export default function Sidebar() {
  const navigate = useNavigate();
  const role = localStorage.getItem("user_role") || "analyst";

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col h-screen sticky top-0">
      <div className="h-2 bg-[#00664F] w-full"></div>

      <div className="p-6 border-b border-slate-100 flex items-center gap-3 bg-slate-50/50">
        <div className="text-3xl font-extrabold text-[#00664F] select-none">★</div>
        <div>
          <div className="text-sm font-black text-[#00664F] tracking-tight leading-tight">STAR ASSURANCES</div>
          <div className="text-[10px] text-slate-400 font-mono font-bold tracking-wider uppercase mt-0.5">Cyber SOC Platform</div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1.5">
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to} to={to} end={to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-150 ${
                isActive
                  ? "bg-[#00664F]/10 text-[#00664F] font-bold border-l-4 border-[#00664F]"
                  : "text-slate-500 hover:text-slate-900 hover:bg-slate-50"
              }`
            }
          >
            <Icon size={18} className="stroke-[2.25]" />
            {label}
          </NavLink>
        ))}

        {/* Visible uniquement pour l'admin */}
        {role === "admin" && (
          <NavLink
            to="/admin/users"
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-150 ${
                isActive
                  ? "bg-[#00664F]/10 text-[#00664F] font-bold border-l-4 border-[#00664F]"
                  : "text-slate-500 hover:text-slate-900 hover:bg-slate-50"
              }`
            }
          >
            <Users size={18} className="stroke-[2.25]" />
            Gestion des comptes
          </NavLink>
        )}
      </nav>

      <div className="p-4 border-t border-slate-100 bg-slate-50/50">
        <div className="flex items-center gap-2 px-2 mb-3">
          <Shield size={14} className="text-[#00664F]" />
          <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">{role}</span>
        </div>
        <button
          onClick={() => { localStorage.clear(); navigate("/login"); }}
          className="flex items-center gap-2 text-xs text-slate-400 hover:text-[#991B1B] font-medium px-2 py-1.5 rounded-lg w-full transition-colors"
        >
          <LogOut size={14} />
          Fermer la session
        </button>
      </div>
    </aside>
  );
}