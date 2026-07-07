import { useState } from "react";
import { useSearchParams, useNavigate, Link } from "react-router-dom";
import { KeyRound, Loader2 } from "lucide-react";
import apiClient from "../api/client";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get("token");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await apiClient.post("/api/auth/reset-password", { token, new_password: password });
      setDone(true);
      setTimeout(() => navigate("/login"), 2500);
    } catch (err) {
      setError(err.response?.data?.detail || "Échec de la réinitialisation.");
    } finally {
      setLoading(false);
    }
  }

  if (!token) {
    return (
      <div className="min-h-screen bg-[#F4F7F6] flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-xl border border-slate-200/60 p-8 text-center space-y-3">
          <p className="text-sm font-semibold text-[#991B1B]">Lien invalide ou incomplet.</p>
          <Link to="/login" className="text-xs font-bold text-[#00664F]">Retour à la connexion</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F4F7F6] flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md h-2 bg-[#00664F] rounded-t-2xl"></div>
      <div className="bg-white w-full max-w-md rounded-b-2xl shadow-xl border border-slate-200/60 p-8 space-y-6">
        <h1 className="text-lg font-black text-[#00664F] text-center">Nouveau mot de passe</h1>

        {done ? (
          <div className="bg-[#00664F]/[0.05] border border-[#00664F]/20 text-[#00664F] text-xs font-semibold p-4 rounded-xl text-center">
            Mot de passe mis à jour. Redirection vers la connexion...
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="bg-[#991B1B]/[0.05] border border-[#991B1B]/20 text-[#991B1B] text-xs font-semibold p-3 rounded-xl">
                {error}
              </div>
            )}
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400">
                <KeyRound size={16} />
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Nouveau mot de passe (12+ car., maj., min., chiffre, spécial)"
                className="w-full bg-slate-50 border border-slate-200 rounded-xl py-2.5 pl-10 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F]"
                required
              />
            </div>
            <button type="submit" disabled={loading}
              className="w-full bg-[#00664F] hover:bg-[#004D3C] disabled:bg-slate-400 text-white font-bold text-sm py-3 rounded-xl flex items-center justify-center gap-2">
              {loading ? <Loader2 size={16} className="animate-spin" /> : "Valider"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}