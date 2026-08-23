import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { LoadingState } from "./components/ui";

const SocPage = lazy(() => import("./pages/SocPage"));
const AlertsPage = lazy(() => import("./pages/AlertsPage"));
const HuntPage = lazy(() => import("./pages/HuntPage"));
const IncidentsPage = lazy(() => import("./pages/IncidentsPage"));
const RulesPage = lazy(() => import("./pages/RulesPage"));
const AuditPage = lazy(() => import("./pages/AuditPage"));
const CollectorsPage = lazy(() => import("./pages/CollectorsPage"));
const ThreatIntelPage = lazy(() => import("./pages/ThreatIntelPage"));
const UebaPage = lazy(() => import("./pages/UebaPage"));
const EvidencePage = lazy(() => import("./pages/EvidencePage"));
const SoarPage = lazy(() => import("./pages/SoarPage"));
const AISocPage = lazy(() => import("./pages/AISocPage"));
const SystemPage = lazy(() => import("./pages/SystemPage"));
const CasesPage = lazy(() => import("./pages/CasesPage"));
const AssetsPage = lazy(() => import("./pages/AssetsPage"));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage"));

export default function App() {
  return (
    <Suspense fallback={<div className="route-loader"><LoadingState rows={6} /></div>}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/soc" replace />} />
          <Route path="/soc" element={<SocPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/hunt" element={<HuntPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/collectors" element={<CollectorsPage />} />
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/ueba" element={<UebaPage />} />
          <Route path="/evidence" element={<EvidencePage />} />
          <Route path="/soar" element={<SoarPage />} />
          <Route path="/ai-soc" element={<AISocPage />} />
          <Route path="/system" element={<SystemPage />} />
          <Route path="/cases" element={<CasesPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
