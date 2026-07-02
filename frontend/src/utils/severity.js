/**
 * Échelle de sévérité officielle — Cyber SOC STAR Assurances.
 *
 * Source unique de vérité pour les couleurs de sévérité dans toute
 * l'application. N'utilise QUE les trois accents définis par la charte
 * graphique (rouge mat, orange mat, bleu ardoise) — aucune teinte
 * fluorescente ou couleur Tailwind par défaut.
 */

const TIERS = {
  critical: {
    key: "critical",
    label: "Critique",
    hex: "#991B1B",
    text: "text-[#991B1B]",
    bg: "bg-[#991B1B]/[0.06]",
    border: "border-[#991B1B]/20",
    dot: "bg-[#991B1B]",
  },
  medium: {
    key: "medium",
    label: "Moyen",
    hex: "#C2410C",
    text: "text-[#C2410C]",
    bg: "bg-[#C2410C]/[0.06]",
    border: "border-[#C2410C]/20",
    dot: "bg-[#C2410C]",
  },
  info: {
    key: "info",
    label: "Faible",
    hex: "#1E3A8A",
    text: "text-[#1E3A8A]",
    bg: "bg-[#1E3A8A]/[0.06]",
    border: "border-[#1E3A8A]/20",
    dot: "bg-[#1E3A8A]",
  },
};

/**
 * Renvoie le palier de sévérité (couleurs + libellé) pour une note /10.
 * Seuils : ≥8 Critique, ≥5 Moyen, sinon Faible.
 */
export function getSeverityTier(severity = 0) {
  if (severity >= 8) return TIERS.critical;
  if (severity >= 5) return TIERS.medium;
  return TIERS.info;
}

export function getUrgencyLabel(severity = 0) {
  if (severity >= 8) return "Immédiate";
  if (severity >= 5) return "Modérée";
  return "Standard";
}

export const SEVERITY_TIERS = TIERS;
