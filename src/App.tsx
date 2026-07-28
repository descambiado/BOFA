import { Suspense, lazy } from "react";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AppHeader } from "./components/Navigation/AppHeader";
import { ProtectedRoute } from "./components/ProtectedRoute";
import Index from "./pages/Index";

const Scripts = lazy(() => import("./pages/Scripts"));
const Flows = lazy(() => import("./pages/Flows"));
const Labs = lazy(() => import("./pages/Labs"));
const History = lazy(() => import("./pages/History"));
const Study = lazy(() => import("./pages/Study"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Health = lazy(() => import("./pages/Health"));
const NotFound = lazy(() => import("./pages/NotFound"));
const Library = lazy(() => import("./pages/Library"));
const Bounty = lazy(() => import("./pages/Bounty"));
const Fabric = lazy(() => import("./pages/Fabric"));

const queryClient = new QueryClient();

function RouteFallback() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-6">
      <div className="w-full max-w-md rounded-3xl border border-primary/20 bg-slate-950/80 p-8 text-center shadow-2xl shadow-cyan-950/20">
        <div className="mx-auto mb-4 h-12 w-12 rounded-full border border-cyan-400/30 bg-cyan-400/10" />
        <h2 className="text-xl font-semibold text-white">Cargando espacio de trabajo</h2>
        <p className="mt-2 text-sm text-slate-300">
          BOFA esta cargando esta superficie bajo demanda para mantener el arranque mas ligero.
        </p>
      </div>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <div className="min-h-screen bg-gradient-dark text-foreground">
          <Toaster />
          <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <AppHeader />
            <main className="relative overflow-hidden">
              <div className="pointer-events-none fixed inset-0 bg-gradient-dark opacity-90" />
              <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(ellipse_at_top,hsl(var(--bofa-cyber)/0.1),transparent_50%)]" />

              <Suspense fallback={<RouteFallback />}>
                <Routes>
                  <Route path="/" element={<Index />} />
                  <Route
                    path="/dashboard"
                    element={
                      <ProtectedRoute>
                        <Dashboard />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/health"
                    element={
                      <ProtectedRoute>
                        <Health />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/fabric"
                    element={
                      <ProtectedRoute>
                        <Fabric />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/scripts"
                    element={
                      <ProtectedRoute>
                        <Scripts />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/flows"
                    element={
                      <ProtectedRoute>
                        <Flows />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/library"
                    element={
                      <ProtectedRoute>
                        <Library />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/bounty"
                    element={
                      <ProtectedRoute>
                        <Bounty />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/labs"
                    element={
                      <ProtectedRoute>
                        <Labs />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/history"
                    element={
                      <ProtectedRoute>
                        <History />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="/study"
                    element={
                      <ProtectedRoute>
                        <Study />
                      </ProtectedRoute>
                    }
                  />
                  <Route path="*" element={<NotFound />} />
                </Routes>
              </Suspense>
            </main>
          </BrowserRouter>
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
