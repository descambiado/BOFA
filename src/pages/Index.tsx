import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { LoginDialog } from "@/components/auth/LoginDialog";
import { authService } from "@/services/api";
import { APP_CONFIG } from "@/config/app";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ArrowRight,
  Brain,
  Crosshair,
  FileSearch,
  FolderSearch,
  GitCompareArrows,
  Shield,
  Sparkles,
  Terminal,
} from "lucide-react";

const capabilityCards = [
  {
    title: "Runtime real",
    description: "Scripts, flows, labs y evidencia viven bajo el mismo control plane local-first.",
    icon: <Terminal className="h-8 w-8" />,
  },
  {
    title: "Bounty workspaces",
    description: "Snapshots, deltas, findings y review queue para priorizar mejor y repetir menos.",
    icon: <Crosshair className="h-8 w-8" />,
  },
  {
    title: "IA con contexto",
    description: "Copilotos local/API para trabajar sobre evidencia y memoria operativa, no sobre humo.",
    icon: <Brain className="h-8 w-8" />,
  },
];

const workflowSteps = [
  {
    title: "1. Importa contexto",
    description: "Scope, disclosed reports, URLs, JS endpoints o notas de programa.",
    icon: <FolderSearch className="h-6 w-6" />,
  },
  {
    title: "2. Mira que cambio",
    description: "BOFA conserva snapshots y resalta deltas utiles para no empezar de cero.",
    icon: <GitCompareArrows className="h-6 w-6" />,
  },
  {
    title: "3. Decide mejor",
    description: "Review queue, report candidates, evidencia y exportes para el siguiente paso manual.",
    icon: <FileSearch className="h-6 w-6" />,
  },
];

const Index = () => {
  const navigate = useNavigate();
  const [showLogin, setShowLogin] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(authService.isAuthenticated());

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    authService.logout();
    setIsAuthenticated(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-cyan-950/30 to-slate-900 text-white">
      <section className="relative overflow-hidden border-b border-cyan-500/10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.14),transparent_35%),radial-gradient(circle_at_bottom_right,rgba(14,165,233,0.12),transparent_30%)]" />
        <div className="relative container mx-auto px-6 py-20">
          <div className="max-w-5xl space-y-8">
            <div className="flex flex-wrap items-center gap-3">
              <Badge className="border border-cyan-400/20 bg-cyan-500/10 text-cyan-200">
                {APP_CONFIG.fullName}
              </Badge>
              <Badge className="border border-slate-700 bg-slate-900/70 text-slate-200">
                v{APP_CONFIG.version}
              </Badge>
            </div>

            <div className="space-y-5">
              <h1 className="max-w-4xl text-5xl font-bold tracking-tight text-white md:text-7xl">
                Duplicate-aware web/API hunting with evidence, deltas and AI copilots.
              </h1>
              <p className="max-w-3xl text-lg text-slate-300 md:text-xl">
                BOFA no intenta reemplazar todas las herramientas. Intenta darte un cockpit local-first donde la
                ejecucion, la memoria del programa y la evidencia pertenezcan a la misma historia.
              </p>
            </div>

            <div className="flex flex-wrap gap-3 text-sm text-slate-200">
              <Badge className="border border-slate-700 bg-slate-900/70">Snapshots and deltas</Badge>
              <Badge className="border border-slate-700 bg-slate-900/70">Review queue</Badge>
              <Badge className="border border-slate-700 bg-slate-900/70">Evidence exports</Badge>
              <Badge className="border border-slate-700 bg-slate-900/70">Local/API AI</Badge>
              <Badge className="border border-slate-700 bg-slate-900/70">Control plane</Badge>
            </div>

            {isAuthenticated ? (
              <div className="flex flex-col gap-4 sm:flex-row">
                <Button
                  size="lg"
                  onClick={() => navigate("/dashboard")}
                  className="bg-cyan-500 text-slate-950 hover:bg-cyan-400"
                >
                  Abrir overview
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
                <Button
                  size="lg"
                  variant="outline"
                  onClick={() => navigate("/bounty")}
                  className="border-cyan-400 text-cyan-200 hover:bg-cyan-400 hover:text-slate-950"
                >
                  Ir a bounty
                </Button>
                <Button
                  size="lg"
                  variant="outline"
                  onClick={() => navigate("/scripts")}
                  className="border-slate-600 text-slate-200 hover:bg-slate-800"
                >
                  Explorar scripts
                </Button>
                <Button
                  size="lg"
                  variant="outline"
                  onClick={handleLogout}
                  className="border-red-500/40 text-red-200 hover:bg-red-500/10"
                >
                  Cerrar sesion ({authService.getCurrentUser()?.username})
                </Button>
              </div>
            ) : (
              <div className="flex flex-col gap-4 sm:flex-row">
                <Button
                  size="lg"
                  className="bg-cyan-500 text-slate-950 hover:bg-cyan-400"
                  onClick={() => setShowLogin(true)}
                >
                  Iniciar sesion
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
                <div className="flex items-center text-sm text-slate-400">
                  El login abre el runtime real. No estamos vendiendo una demo hueca.
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="container mx-auto px-6 py-16">
        <div className="mb-10 max-w-3xl">
          <h2 className="text-3xl font-bold text-cyan-200">Donde BOFA tiene sentido</h2>
          <p className="mt-3 text-slate-300">
            El proyecto gana cuando conecta herramientas, estado y decisiones. No cuando intenta ser un catalogo
            infinito.
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {capabilityCards.map((item) => (
            <Card key={item.title} className="border-cyan-500/10 bg-slate-950/70">
              <CardHeader>
                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-500/10 text-cyan-200">
                  {item.icon}
                </div>
                <CardTitle className="text-cyan-200">{item.title}</CardTitle>
                <CardDescription className="text-slate-300">{item.description}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
      </section>

      <section className="border-y border-cyan-500/10 bg-slate-950/60">
        <div className="container mx-auto px-6 py-16">
          <div className="mb-10 max-w-3xl">
            <h2 className="text-3xl font-bold text-cyan-200">Flujo flagship</h2>
            <p className="mt-3 text-slate-300">
              El mejor BOFA no es un slideshow. Es el que te ayuda a conservar contexto, detectar novedad y exportar
              evidencia sin desmontar el workspace.
            </p>
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            {workflowSteps.map((step) => (
              <Card key={step.title} className="border-slate-800 bg-slate-900/70">
                <CardHeader>
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-slate-800 text-cyan-200">
                    {step.icon}
                  </div>
                  <CardTitle className="text-white">{step.title}</CardTitle>
                  <CardDescription className="text-slate-300">{step.description}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="container mx-auto px-6 py-16">
        <div className="grid gap-6 lg:grid-cols-[1.5fr,1fr]">
          <Card className="border-slate-800 bg-slate-950/70">
            <CardHeader>
              <CardTitle className="text-cyan-200">Que puedes abrir hoy</CardTitle>
              <CardDescription className="text-slate-300">
                La app ya tiene superficies reales que encajan entre si.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                <p className="font-medium text-white">Overview</p>
                <p className="mt-2 text-sm text-slate-400">Runs, queue, bounty signal y actividad reciente desde la API.</p>
              </div>
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                <p className="font-medium text-white">Bounty</p>
                <p className="mt-2 text-sm text-slate-400">Imports, snapshots, what changed y review queue alineados.</p>
              </div>
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                <p className="font-medium text-white">Scripts</p>
                <p className="mt-2 text-sm text-slate-400">Catalogo cargado desde el runtime, no desde mocks del cliente.</p>
              </div>
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                <p className="font-medium text-white">Library</p>
                <p className="mt-2 text-sm text-slate-400">Codigo fuente y metadata expuestos por la misma verdad del backend.</p>
              </div>
            </CardContent>
          </Card>

          <Card className="border-cyan-500/10 bg-gradient-to-br from-cyan-950/50 to-slate-950">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-cyan-200">
                <Sparkles className="h-5 w-5" />
                BOFA en una frase
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-sm text-slate-300">
              <p>
                Un runtime local-first para trabajo de seguridad web/API con memoria operativa, evidencia y copilotos
                de IA.
              </p>
              <div className="rounded-2xl border border-cyan-500/10 bg-slate-950/60 p-4">
                <p className="font-medium text-white">Construido por {APP_CONFIG.developer.name}</p>
                <p className="mt-2 text-slate-400">
                  Menos claims grandilocuentes. Mas workflow reproducible y señal real.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Badge className="border border-cyan-500/10 bg-slate-950/70 text-cyan-200">local-first</Badge>
                <Badge className="border border-cyan-500/10 bg-slate-950/70 text-cyan-200">duplicate-aware</Badge>
                <Badge className="border border-cyan-500/10 bg-slate-950/70 text-cyan-200">evidence</Badge>
                <Badge className="border border-cyan-500/10 bg-slate-950/70 text-cyan-200">AI copilots</Badge>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      <footer className="border-t border-slate-800 bg-slate-950/60 py-8">
        <div className="container mx-auto flex flex-col gap-4 px-6 text-sm text-slate-400 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-cyan-200" />
            <span>
              {APP_CONFIG.name} v{APP_CONFIG.version} · {APP_CONFIG.fullName}
            </span>
          </div>
          <div>Built by {APP_CONFIG.developer.name} for real workflows, not synthetic hype.</div>
        </div>
      </footer>

      <LoginDialog open={showLogin} onOpenChange={setShowLogin} onSuccess={handleLoginSuccess} />
    </div>
  );
};

export default Index;
