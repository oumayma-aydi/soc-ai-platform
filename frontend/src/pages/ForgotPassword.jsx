// src/pages/ForgotPassword.jsx
import { useState } from "react";
import { Link } from "react-router-dom";
import { Mail, Loader2, ArrowLeft } from "lucide-react";
import apiClient from "../api/client";

export default function ForgotPassword() {
  const [identifier, setIdentifier] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    try {
      await apiClient.post("/api/auth/forgot-password", { username_or_email: identifier });
    } catch {
      // Réponse volontairement générique même en cas d'erreur — ne pas confirmer
      // l'existence ou non d'un compte (bonne pratique de sécurité).
    } finally {
      setLoading(false);
      setSent(true);
    }
  }

  return (
    <div className="min-h-screen bg-[#F4F7F6] flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md h-2 bg-[#00664F] rounded-t-2xl"></div>
      <div className="bg-white w-full max-w-md rounded-b-2xl shadow-xl border border-slate-200/60 p-8 space-y-6">
        <div className="text-center space-y-2">
          <h1 className="text-lg font-black text-[#00664F] tracking-tight">Mot de passe oublié</h1>
          <p className="text-xs text-slate-500">
            Selon votre rôle, un lien de réinitialisation ou une notification à l'administrateur sera envoyé.
          </p>
        </div>

        {sent ? (
          <div className="bg-[#00664F]/[0.05] border border-[#00664F]/20 text-[#00664F] text-xs font-semibold p-4 rounded-xl text-center">
            Si ce compte existe, la procédure de réinitialisation a été initiée. Consultez votre boîte mail ou contactez votre administrateur.
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400">
                <Mail size={16} />
              </span>
              <input
                type="text"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                placeholder="Identifiant ou e-mail"
                className="w-full bg-slate-50 border border-slate-200 rounded-xl py-2.5 pl-10 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F]"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-[#00664F] hover:bg-[#004D3C] disabled:bg-slate-400 text-white font-bold text-sm py-3 rounded-xl flex items-center justify-center gap-2"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : "Envoyer la demande"}
            </button>
          </form>
        )}

        <Link to="/login" className="flex items-center justify-center gap-1.5 text-xs font-bold text-slate-500 hover:text-[#00664F] pt-2 border-t border-slate-100">
          <ArrowLeft size={12} /> Retour à la connexion
        </Link>
      </div>
    </div>
  );
}