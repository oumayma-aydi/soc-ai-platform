import { useState, useEffect } from "react";
import { UserPlus, Loader2, Users, Trash2, KeyRound, ShieldCheck, Mail } from "lucide-react";
import apiClient from "../api/client";

const ROLES = [
  { value: "analyst", label: "Analyste" },
  { value: "auditor", label: "Auditeur" },
];

function extractErrorMessage(err, fallback) {
  const detail = err.response?.data?.detail;
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => d.msg || JSON.stringify(d)).join(" · ");
  }
  return fallback;
}

function ConfirmPasswordModal({ open, onConfirm, onCancel, actionLabel, busy }) {
  const [password, setPassword] = useState("");

  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-xl border border-slate-200 p-6 w-full max-w-sm space-y-4">
        <h3 className="text-sm font-black text-[#00664F] uppercase tracking-wider">
          Confirmation requise
        </h3>
        <p className="text-xs text-slate-500">
          Pour confirmer « {actionLabel} », ressaisissez votre mot de passe administrateur.
        </p>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Votre mot de passe"
          className="w-full border border-slate-200 rounded-lg px-3 py-2 text-sm"
          autoFocus
        />
        <div className="flex gap-2 justify-end">
          <button onClick={onCancel} className="text-xs font-bold text-slate-500 px-3 py-2">
            Annuler
          </button>
          <button
            onClick={() => onConfirm(password)}
            disabled={busy || !password}
            className="bg-[#00664F] hover:bg-[#004D3C] disabled:bg-slate-400 text-white text-xs font-bold px-4 py-2 rounded-lg"
          >
            {busy ? "Vérification..." : "Confirmer"}
          </button>
        </div>
      </div>
    </div>
  );
}

function CreateAccountForm({ onCreated }) {
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "analyst" });
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);
    try {
      const res = await apiClient.post("/api/auth/register", form);
      setStatus({ type: "success", msg: `Compte ${res.data.username} créé avec succès (rôle : ${res.data.role}).` });
      setForm({ username: "", email: "", password: "", role: "analyst" });
      onCreated?.();
    } catch (err) {
      setStatus({ type: "error", msg: extractErrorMessage(err, "Échec de la création du compte.") });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-5">
      <h2 className="text-sm font-black uppercase tracking-wider text-[#00664F] flex items-center gap-2">
        <UserPlus size={16} /> Créer un compte
      </h2>

      {status && (
        <div className={`text-xs font-semibold p-3 rounded-xl border ${
          status.type === "success"
            ? "bg-[#00664F]/[0.05] border-[#00664F]/20 text-[#00664F]"
            : "bg-[#991B1B]/[0.05] border-[#991B1B]/20 text-[#991B1B]"
        }`}>
          {status.msg}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <input name="username" value={form.username} onChange={handleChange} placeholder="Identifiant"
          className="w-full bg-slate-50 border border-slate-200 rounded-xl py-2.5 px-4 text-sm focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F]" required />
        <input name="email" type="email" value={form.email} onChange={handleChange} placeholder="Adresse e-mail STAR"
          className="w-full bg-slate-50 border border-slate-200 rounded-xl py-2.5 px-4 text-sm focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F]" required />
        <input name="password" type="password" value={form.password} onChange={handleChange} placeholder="Mot de passe temporaire (12+ caractères)"
          className="w-full bg-slate-50 border border-slate-200 rounded-xl py-2.5 px-4 text-sm focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F]" required />
        <select name="role" value={form.role} onChange={handleChange}
          className="w-full bg-slate-50 border border-slate-200 rounded-xl py-2.5 px-4 text-sm focus:outline-none focus:ring-2 focus:ring-[#00664F]/20 focus:border-[#00664F]">
          {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
        </select>
        <button type="submit" disabled={loading}
          className="w-full bg-[#00664F] hover:bg-[#004D3C] disabled:bg-slate-400 text-white font-bold text-sm py-3 rounded-xl transition-all flex items-center justify-center gap-2">
          {loading ? <Loader2 size={16} className="animate-spin" /> : <UserPlus size={16} />}
          {loading ? "Création..." : "Créer le compte"}
        </button>
      </form>
    </div>
  );
}

function AccountRow({ account, onChanged }) {
  const [editingRole, setEditingRole] = useState(false);
  const [editingPassword, setEditingPassword] = useState(false);
  const [editingEmail, setEditingEmail] = useState(false);
  const [newRole, setNewRole] = useState(account.role);
  const [newPassword, setNewPassword] = useState("");
  const [newEmail, setNewEmail] = useState(account.email);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pendingAction, setPendingAction] = useState(null); // "role" | "password" | "email" | "delete" | "unlock" | null

  async function runConfirmedAction(confirmPassword) {
    setBusy(true);
    setError("");
    try {
      if (pendingAction === "role") {
        await apiClient.patch(`/api/auth/users/${account.id}/role`, {
          role: newRole,
          confirm_password: confirmPassword,
        });
        setEditingRole(false);
        onChanged();
      } else if (pendingAction === "password") {
        await apiClient.post(`/api/auth/admin/set-password/${account.id}`, {
          new_password: newPassword,
          confirm_password: confirmPassword,
        });
        setEditingPassword(false);
        setNewPassword("");
      } else if (pendingAction === "email") {
        await apiClient.patch(`/api/auth/users/${account.id}/email`, {
          new_email: newEmail,
          confirm_password: confirmPassword,
        });
        setEditingEmail(false);
        onChanged();
      } else if (pendingAction === "delete") {
        await apiClient.delete(`/api/auth/users/${account.id}`, {
          data: { confirm_password: confirmPassword },
        });
        onChanged();
      } else if (pendingAction === "unlock") {
        await apiClient.post(`/api/auth/admin/unlock/${account.id}`, { confirm_password: confirmPassword });
        onChanged();
      }
      setPendingAction(null);
    } catch (err) {
      setError(extractErrorMessage(err, "Échec de l'action."));
      setPendingAction(null);
    } finally {
      setBusy(false);
    }
  }

  const roleBadge = {
    admin: "bg-[#00664F]/[0.06] text-[#00664F] border-[#00664F]/20",
    analyst: "bg-[#1E3A8A]/[0.06] text-[#1E3A8A] border-[#1E3A8A]/20",
    auditor: "bg-[#C2410C]/[0.06] text-[#C2410C] border-[#C2410C]/20",
  }[account.role] || "bg-slate-100 text-slate-600 border-slate-200";

  const actionLabels = {
    role: "changement d'accès",
    password: "réinitialisation du mot de passe",
    email: "changement d'e-mail",
    delete: "suppression du compte",
    unlock: "déblocage du compte",
  };

  return (
    <div className="border border-slate-100 rounded-xl p-4 space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <p className="text-sm font-bold text-slate-800">{account.username}</p>
          <p className="text-xs text-slate-500">{account.email}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-[10px] font-black uppercase tracking-wider px-2 py-1 rounded-md border ${roleBadge}`}>
            {account.role}
          </span>
          {account.is_active === 0 && (
            <span className="text-[10px] font-black uppercase tracking-wider px-2 py-1 rounded-md border bg-[#991B1B]/[0.06] text-[#991B1B] border-[#991B1B]/20">
              Bloqué
            </span>
          )}
        </div>
      </div>

      {error && <p className="text-[11px] font-semibold text-[#991B1B]">{error}</p>}

      {editingRole ? (
        <div className="flex items-center gap-2">
          <select value={newRole} onChange={(e) => setNewRole(e.target.value)}
            className="flex-1 border border-slate-200 rounded-lg px-2 py-1.5 text-xs">
            {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
          </select>
          <button onClick={() => setPendingAction("role")}
            className="bg-[#00664F] text-white text-xs font-bold px-3 py-1.5 rounded-lg">
            Valider
          </button>
          <button onClick={() => setEditingRole(false)} className="text-xs text-slate-400 px-2">Annuler</button>
        </div>
      ) : editingPassword ? (
        <div className="flex items-center gap-2">
          <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
            placeholder="Nouveau mot de passe" className="flex-1 border border-slate-200 rounded-lg px-2 py-1.5 text-xs" />
          <button onClick={() => setPendingAction("password")} disabled={!newPassword}
            className="bg-[#00664F] text-white text-xs font-bold px-3 py-1.5 rounded-lg disabled:opacity-50">
            Valider
          </button>
          <button onClick={() => setEditingPassword(false)} className="text-xs text-slate-400 px-2">Annuler</button>
        </div>
      ) : editingEmail ? (
        <div className="flex items-center gap-2">
          <input type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)}
            placeholder="Nouvel e-mail" className="flex-1 border border-slate-200 rounded-lg px-2 py-1.5 text-xs" />
          <button onClick={() => setPendingAction("email")} disabled={!newEmail}
            className="bg-[#00664F] text-white text-xs font-bold px-3 py-1.5 rounded-lg disabled:opacity-50">
            Valider
          </button>
          <button onClick={() => setEditingEmail(false)} className="text-xs text-slate-400 px-2">Annuler</button>
        </div>
      ) : (
        <div className="flex items-center gap-3 pt-1 border-t border-slate-50 flex-wrap">
          <button onClick={() => setEditingRole(true)}
            className="flex items-center gap-1 text-[11px] font-bold text-[#00664F] hover:underline">
            <ShieldCheck size={12} /> Changer l'accès
          </button>
          <button onClick={() => setEditingEmail(true)}
            className="flex items-center gap-1 text-[11px] font-bold text-[#00664F] hover:underline">
            <Mail size={12} /> Changer l'e-mail
          </button>
          <button onClick={() => setEditingPassword(true)}
            className="flex items-center gap-1 text-[11px] font-bold text-[#00664F] hover:underline">
            <KeyRound size={12} /> Réinitialiser le mot de passe
          </button>
          {account.is_active === 0 && (
            <button onClick={() => setPendingAction("unlock")}
              className="flex items-center gap-1 text-[11px] font-bold text-[#00664F] hover:underline">
              <ShieldCheck size={12} /> Débloquer
            </button>
          )}
          <button onClick={() => setPendingAction("delete")}
            className="flex items-center gap-1 text-[11px] font-bold text-[#991B1B] hover:underline ml-auto">
            <Trash2 size={12} /> Supprimer
          </button>
        </div>
      )}

      <ConfirmPasswordModal
        open={!!pendingAction}
        busy={busy}
        actionLabel={actionLabels[pendingAction] || ""}
        onConfirm={runConfirmedAction}
        onCancel={() => setPendingAction(null)}
      />
    </div>
  );
}

function AccountsList({ refreshKey }) {
  const [accounts, setAccounts] = useState([]);
  const [visible, setVisible] = useState(false);
  const [loading, setLoading] = useState(false);

  const load = () => {
    setLoading(true);
    apiClient.get("/api/auth/users")
      .then((res) => setAccounts(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { if (visible) load(); }, [visible, refreshKey]);

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-4">
      <button
        onClick={() => setVisible((v) => !v)}
        className="w-full flex items-center justify-between text-sm font-black uppercase tracking-wider text-[#00664F]"
      >
        <span className="flex items-center gap-2"><Users size={16} /> Comptes actuels</span>
        <span className="text-xs font-bold text-slate-400">{visible ? "Masquer" : "Afficher"}</span>
      </button>

      {visible && (
        loading ? (
          <p className="text-xs text-slate-400 text-center py-6">Chargement...</p>
        ) : accounts.length === 0 ? (
          <p className="text-xs text-slate-400 text-center py-6">Aucun compte trouvé.</p>
        ) : (
          <div className="space-y-3">
            {accounts.map((a) => (
              <AccountRow key={a.id} account={a} onChanged={load} />
            ))}
          </div>
        )
      )}
    </div>
  );
}

export default function UserManagement() {
  const [refreshKey, setRefreshKey] = useState(0);

  return (
    <div className="max-w-xl mx-auto space-y-6 pb-12">
      <CreateAccountForm onCreated={() => setRefreshKey((k) => k + 1)} />
      <AccountsList refreshKey={refreshKey} />
    </div>
  );
}