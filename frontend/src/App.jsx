import { Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import Analysis from "./pages/Analysis";
import Report from "./pages/Report";
import Login from "./pages/Login";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import UserManagement from "./pages/UserManagement";

function isTokenValid(token) {
  if (!token) return false;
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    if (!payload.exp) return true;
    return Date.now() < payload.exp * 1000;
  } catch {
    return false;
  }
}

// Layout Privé Sécurisé — vérifie la présence ET la validité du token,
// et optionnellement restreint l'accès à une liste de rôles autorisés.
function PrivateLayout({ children, allowedRoles }) {
  const token = localStorage.getItem("access_token");
  const role = localStorage.getItem("user_role");

  if (!isTokenValid(token)) {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("user_role");
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(role)) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="flex h-screen bg-[#F4F7F6]">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-6">{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      {/* Routes publiques */}
      <Route path="/login" element={<Login />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />

      {/* Routes protégées */}
      <Route path="/" element={<PrivateLayout><Home /></PrivateLayout>} />
      <Route path="/dashboard" element={<PrivateLayout><Dashboard /></PrivateLayout>} />
      <Route path="/analysis" element={<PrivateLayout><Analysis /></PrivateLayout>} />
      <Route path="/report/:id" element={<PrivateLayout><Report /></PrivateLayout>} />
      <Route
        path="/admin/users"
        element={<PrivateLayout allowedRoles={["admin"]}><UserManagement /></PrivateLayout>}
      />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}