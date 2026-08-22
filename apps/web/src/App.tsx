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
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
