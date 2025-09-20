
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AppHeader } from "./components/Navigation/AppHeader";
import { ProtectedRoute } from "./components/ProtectedRoute";
import Index from "./pages/Index";
import Scripts from "./pages/Scripts";
import Labs from "./pages/Labs";
import History from "./pages/History";
import Study from "./pages/Study";
import Dashboard from "./pages/Dashboard";
import NotFound from "./pages/NotFound";
import Library from "./pages/Library";

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <div className="min-h-screen bg-gradient-dark text-foreground">
          <Toaster />
          <BrowserRouter>
            <AppHeader />
            <main className="relative overflow-hidden">
              {/* Background Effects */}
              <div className="fixed inset-0 bg-gradient-dark opacity-90 pointer-events-none"></div>
              <div className="fixed inset-0 bg-[radial-gradient(ellipse_at_top,hsl(var(--bofa-cyber)/0.1),transparent_50%)] pointer-events-none"></div>
              
              <Routes>
                <Route path="/" element={<Index />} />
                <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
                <Route path="/scripts" element={<ProtectedRoute><Scripts /></ProtectedRoute>} />
                <Route path="/library" element={<ProtectedRoute><Library /></ProtectedRoute>} />
                <Route path="/labs" element={<ProtectedRoute><Labs /></ProtectedRoute>} />
                <Route path="/history" element={<ProtectedRoute><History /></ProtectedRoute>} />
                <Route path="/study" element={<ProtectedRoute><Study /></ProtectedRoute>} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </main>
          </BrowserRouter>
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
