import { Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import Analysis from "./pages/Analysis";
import Report from "./pages/Report";
import Login from "./pages/Login";

// Layout Privé Sécurisé - Fond clair institutionnel
function PrivateLayout({ children }) {
  const token = localStorage.getItem("access_token");
  
  // Si pas de token, redirection immédiate vers la page de Login
  if (!token) return <Navigate to="/login" replace />;

  return (
    <div className="flex h-screen bg-[#F4F7F6]">
      {/* Barre latérale officielle STAR */}
      <Sidebar />
      {/* Zone d'affichage des dashboards dynamiques */}
      <main className="flex-1 overflow-y-auto p-6">
        {children}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      {/* Route Publique */}
      <Route path="/login" element={<Login />} />

      {/* Routes Protégées par le Layout Cyber */}
      <Route path="/" element={<PrivateLayout><Home /></PrivateLayout>} />
      <Route path="/dashboard" element={<PrivateLayout><Dashboard /></PrivateLayout>} />
      <Route path="/analysis" element={<PrivateLayout><Analysis /></PrivateLayout>} />
      <Route path="/report/:id" element={<PrivateLayout><Report /></PrivateLayout>} />

      {/* Redirection automatique si la route n'existe pas */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
