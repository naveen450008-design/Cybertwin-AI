import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { TaxonomyBanner } from './components/TaxonomyBanner';

// Pages
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { AdminPage } from './pages/AdminPage';
import { ForbiddenPage } from './pages/ForbiddenPage';
import { IngestionDemoPage } from './pages/IngestionDemoPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { IncidentDetailPage } from './pages/IncidentDetailPage';
import { SimulationConsolePage } from './pages/SimulationConsolePage';
import { AuditLedgerPage } from './pages/AuditLedgerPage';
import { IPIntelligencePage } from './pages/IPIntelligencePage';

const AppLayout: React.FC = () => {
  return (
    <div className="flex flex-col min-h-screen bg-[#0B0F17] text-gray-100">
      <TaxonomyBanner />
      <Navbar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 p-6 overflow-y-auto bg-[#0B0F17]">
          <div className="max-w-7xl mx-auto">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Login Route */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/403" element={<ForbiddenPage />} />

          {/* Protected Routes inside AppLayout */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route path="/" element={<DashboardPage />} />

              {/* IP Threat Intelligence */}
              <Route path="/ip-intelligence" element={<IPIntelligencePage />} />

              {/* Incidents Module */}
              <Route path="/incidents" element={<IncidentsPage />} />
              <Route path="/incidents/:id" element={<IncidentDetailPage />} />

              {/* Simulation Module */}
              <Route path="/simulation" element={<SimulationConsolePage />} />

              {/* Audit Ledger */}
              <Route path="/audit" element={<AuditLedgerPage />} />

              {/* Synthetic Ingestion Demo (Phase 2) */}
              <Route path="/ingestion-demo" element={<IngestionDemoPage />} />

              {/* Admin-Only Gated Route */}
              <Route element={<ProtectedRoute requiredRole="Security Admin" />}>
                <Route path="/admin" element={<AdminPage />} />
              </Route>
            </Route>
          </Route>

          {/* Catch-all redirect */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
