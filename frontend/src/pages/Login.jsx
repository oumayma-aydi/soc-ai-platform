import { useState } from "react";
import { useNavigate , Link} from "react-router-dom";
import { Shield, KeyRound, User, Loader2 } from "lucide-react";
import apiClient from "../api/client";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleLogin(e) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await apiClient.post("/api/auth/login", { username, password });
      const { access_token, refresh_token, role } = response.data;

      if (access_token) {
        localStorage.setItem("access_token", access_token);
        if (refresh_token) localStorage.setItem("refresh_token", refresh_token);
        localStorage.setItem("user_role", role || "analyst"); // rôle réel renvoyé par le backend
        navigate("/");
      } else {
        setError("Le serveur n'a pas renvoyé de jeton (token) d'authentification.");
      }
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || "Impossible de contacter le serveur d'authentification.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#F4F7F6] flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md h-2 bg-[#00664F] rounded-t-2xl"></div>

      <div className="bg-white w-full max-w-md rounded-b-2xl shadow-xl border border-slate-200/60 p-8 space-y-6">
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center text-4xl text-[#00664F] font-bold select-none">
            ★
          </div>
          <h1 className="text-xl font-black text-[#00664F] tracking-tight">STAR ASSURANCES</h1>
          <p className="text-xs text-slate-500 font-medium uppercase tracking-wider">
            Contrôle d'Accès · Plateforme SOC AI
          </p>
        </div>

        {error && (
          <div className="bg-[#991B1B]/[0.05] border border-[#991B1B]/20 text-[#991B1B] text-xs font-semibold p-3 rounded-xl text-center">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-bold text-slate-600 uppercase tracking-wide">
              Identifiant
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400">
                <User size={16} />
              </span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Identifiant STAR"
                className="w-full bg-slate-50 border border-slate-200 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F] transition-all"
                disabled={loading}
                required
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-bold text-slate-600 uppercase tracking-wide">
              Mot de passe
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400">
                <KeyRound size={16} />
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-50 border border-slate-200 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F] transition-all"
                disabled={loading}
                required
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[#00664F] hover:bg-[#004D3C] disabled:bg-slate-400 text-white font-bold text-sm py-3 rounded-xl transition-all shadow-md flex items-center justify-center gap-2 mt-2"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Shield size={16} />}
            {loading ? "Vérification..." : "S'authentifier sur le portail"}
          </button>

          <Link to="/forgot-password" className="block text-center text-xs font-semibold text-[#00664F] hover:text-[#004D3C]">
            Mot de passe oublié ?
          </Link>

        </form>
        
        <div className="text-center pt-2 border-t border-slate-100">
          <p className="text-[10px] text-slate-400 font-medium">
            Usage strictement réservé au personnel autorisé de la STAR Assurances.
          </p>
        </div>
      </div>
    </div>
  );
}
