import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, KeyRound, User, Loader2 } from "lucide-react";
import apiClient from "../api/client"; // Assure-toi que le chemin est correct

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
      // Envoi de la requête POST au backend (exactement comme ton curl)
      const response = await apiClient.post("/api/auth/login", {
        username: username,
        password: password,
      });

      // On récupère le token renvoyé par ton API Django/FastAPI
      // Adapte 'response.data.access_token' ou 'response.data.token' selon ce que ton API renvoie
      const token = response.data.access_token || response.data.token;

      if (token) {
        localStorage.setItem("access_token", token);
        localStorage.setItem("user_role", "Administrateur SOC");
        
        // Redirection vers le tableau de bord
        navigate("/");
      } else {
        setError("Le serveur n'a pas renvoyé de jeton (token) d'authentification.");
      }
    } catch (err) {
      console.error(err);
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Impossible de contacter le serveur d'authentification (Erreur backend).");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#F4F7F6] flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md h-2 bg-[#00664F] rounded-t-2xl"></div>

      <div className="bg-white w-full max-w-md rounded-b-2xl shadow-xl border border-slate-200/60 p-8 space-y-6">
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center text-4xl text-[#78BE20] font-bold select-none">
            ★
          </div>
          <h1 className="text-xl font-black text-[#00664F] tracking-tight">
            STAR ASSURANCES
          </h1>
          <p className="text-xs text-slate-500 font-medium uppercase tracking-wider">
            Contrôle d'Accès · Plateforme SOC AI
          </p>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 text-xs font-semibold p-3 rounded-xl text-center">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-bold text-slate-600 uppercase tracking-wide">
              Identifiant de l'analyste
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400">
                <User size={16} />
              </span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Ex: admin"
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
            {loading ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Shield size={16} />
            )}
            {loading ? "Vérification..." : "S'authentifier sur le portail"}
          </button>
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
