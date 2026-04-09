import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/UI/card";
import { Button } from "@/components/UI/button";
import { Badge } from "@/components/UI/badge";
import { StatusBadge } from "@/components/UI/StatusBadge";
import { ActionButton } from "@/components/UI/ActionButton";
import { ScriptExecutionConsole } from "@/components/ScriptExecutionConsole";
import { apiService, useLabs, useRunDetail } from "@/services/api";
import {
  Activity,
  Beaker,
  Cloud,
  Eye,
  Monitor,
  Play,
  RefreshCw,
  Settings,
  Smartphone,
  Square,
  Users,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

const Labs = () => {
  const navigate = useNavigate();
  const { data: labs, isLoading, refetch } = useLabs();
  const [pendingLabId, setPendingLabId] = useState<string | null>(null);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const { data: activeRun } = useRunDetail(activeRunId);

  const runningLabs = useMemo(() => (labs || []).filter((lab) => lab.status === "running"), [labs]);
  const advancedLabs = useMemo(() => (labs || []).filter((lab) => lab.difficulty === "advanced"), [labs]);
  const intermediateLabs = useMemo(() => (labs || []).filter((lab) => lab.difficulty === "intermediate"), [labs]);

  const getCategoryIcon = (category: string) => {
    const icons = {
      network: Monitor,
      mobile: Smartphone,
      cloud: Cloud,
      ctf: Zap,
      web: Eye,
      web_security: Eye,
      purple: Users,
      cloud_native: Cloud,
    };
    return icons[category as keyof typeof icons] || Beaker;
  };

  const getDifficultyColor = (difficulty: string) => {
    const colors = {
      beginner: "bg-green-500",
      intermediate: "bg-yellow-500 text-black",
      advanced: "bg-red-500",
      expert: "bg-fuchsia-600",
    };
    return colors[difficulty as keyof typeof colors] || "bg-gray-500";
  };

  const handleLabAction = async (labId: string, action: "start" | "stop") => {
    try {
      setPendingLabId(labId);
      const result = action === "start" ? await apiService.startLab(labId) : await apiService.stopLab(labId);
      if (result.run_id) {
        setActiveRunId(result.run_id);
      }
      toast.success(result.message);
      await refetch();
    } catch (error) {
      toast.error(action === "start" ? "No se pudo iniciar el lab" : "No se pudo detener el lab");
    } finally {
      setPendingLabId(null);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-slate-900 to-black text-white p-6">
      <div className="container mx-auto max-w-7xl space-y-8">
        <section className="rounded-3xl border border-cyan-500/20 bg-gradient-to-br from-slate-900 via-cyan-950/50 to-slate-950 p-8 shadow-2xl shadow-cyan-950/30">
          <div className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
            <div className="space-y-4">
              <Badge className="border-cyan-400/30 bg-cyan-500/20 text-cyan-200">
                Lab Runtime
              </Badge>
              <div>
                <h1 className="text-4xl font-bold tracking-tight text-white">Laboratorios conectados al control plane</h1>
                <p className="mt-2 max-w-3xl text-base text-slate-300">
                  Cada arranque y parada genera un <span className="text-cyan-300">run</span> trazable. Ya no es una
                  demo de estados locales: el runtime de BOFA gobierna los labs como recursos operativos reales.
                </p>
              </div>
              <div className="flex flex-wrap gap-3 text-sm text-slate-300">
                <span>Labs disponibles: {labs?.length ?? 0}</span>
                <span>Activos: {runningLabs.length}</span>
                <span>Último run: {activeRunId ?? "ninguno"}</span>
              </div>
            </div>

            <div className="grid min-w-[280px] grid-cols-2 gap-3">
              <ActionButton
                icon={<RefreshCw className="w-5 h-5" />}
                title="Recargar"
                description="Refrescar estado"
                onClick={() => refetch()}
              />
              <ActionButton
                icon={<Activity className="w-5 h-5" />}
                title="Historial"
                description="Ver runs"
                onClick={() => navigate("/history")}
              />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <Card className="border-gray-800 bg-gray-900/70">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-cyan-400">{labs?.length ?? 0}</div>
              <div className="text-sm text-gray-400">Labs disponibles</div>
            </CardContent>
          </Card>
          <Card className="border-gray-800 bg-gray-900/70">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-green-400">{runningLabs.length}</div>
              <div className="text-sm text-gray-400">Activos</div>
            </CardContent>
          </Card>
          <Card className="border-gray-800 bg-gray-900/70">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-yellow-400">{intermediateLabs.length}</div>
              <div className="text-sm text-gray-400">Intermedios</div>
            </CardContent>
          </Card>
          <Card className="border-gray-800 bg-gray-900/70">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-red-400">{advancedLabs.length}</div>
              <div className="text-sm text-gray-400">Avanzados</div>
            </CardContent>
          </Card>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1.1fr_0.9fr]">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {isLoading ? (
              Array.from({ length: 4 }).map((_, index) => (
                <Card key={index} className="border-gray-800 bg-gray-900/70 animate-pulse">
                  <CardContent className="p-6">
                    <div className="h-6 w-2/3 rounded bg-gray-800" />
                    <div className="mt-3 h-4 w-full rounded bg-gray-900" />
                    <div className="mt-2 h-4 w-4/5 rounded bg-gray-900" />
                  </CardContent>
                </Card>
              ))
            ) : (
              (labs || []).map((lab) => {
                const CategoryIcon = getCategoryIcon(lab.category);
                const isPending = pendingLabId === lab.id;

                return (
                  <Card key={lab.id} className="border-gray-800 bg-gray-900/70 hover:border-cyan-500/40 transition-all">
                    <CardHeader>
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex items-center gap-3">
                          <CategoryIcon className="h-8 w-8 text-cyan-400" />
                          <div>
                            <CardTitle className="text-cyan-300">{lab.name}</CardTitle>
                            <CardDescription className="mt-1 text-gray-400">{lab.description}</CardDescription>
                          </div>
                        </div>
                        <StatusBadge status={isPending ? "starting" : lab.status} />
                      </div>
                    </CardHeader>

                    <CardContent className="space-y-4">
                      <div className="flex items-center justify-between gap-3">
                        <Badge className={`${getDifficultyColor(lab.difficulty)} text-white`}>
                          {lab.difficulty}
                        </Badge>
                        <span className="text-sm text-gray-400">⏱ {lab.estimated_time || "n/a"}</span>
                      </div>

                      {!!lab.technologies?.length && (
                        <div className="space-y-2">
                          <div className="text-sm text-gray-400">Tecnologías</div>
                          <div className="flex flex-wrap gap-2">
                            {lab.technologies.map((tech) => (
                              <Badge key={tech} variant="outline" className="border-gray-700 text-gray-300">
                                {tech}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {lab.status === "running" && (lab.url || lab.port) && (
                        <div className="rounded-xl bg-black/40 p-3">
                          <div className="text-sm text-gray-400">Acceso</div>
                          <div className="mt-1 break-all font-mono text-cyan-300">
                            {lab.url || `http://localhost:${lab.port}`}
                          </div>
                        </div>
                      )}

                      {lab.message && (
                        <div className="rounded-xl border border-gray-800 bg-black/30 p-3 text-sm text-gray-400">
                          {lab.message}
                        </div>
                      )}

                      <div className="flex items-center gap-3">
                        {lab.status !== "running" ? (
                          <ActionButton
                            icon={<Play className="w-4 h-4" />}
                            title={isPending ? "Iniciando" : "Iniciar"}
                            description="Arrancar lab"
                            onClick={() => handleLabAction(lab.id, "start")}
                            className="flex-1 bg-green-600 hover:bg-green-700"
                          />
                        ) : (
                          <ActionButton
                            icon={<Square className="w-4 h-4" />}
                            title={isPending ? "Deteniendo" : "Detener"}
                            description="Parar lab"
                            onClick={() => handleLabAction(lab.id, "stop")}
                            className="flex-1 bg-red-600 hover:bg-red-700"
                          />
                        )}
                        <ActionButton
                          icon={<Settings className="w-4 h-4" />}
                          title="Runs"
                          description="Ver historial"
                          onClick={() => navigate("/history")}
                        />
                      </div>
                    </CardContent>
                  </Card>
                );
              })
            )}
          </div>

          <div className="space-y-6">
            <Card className="border-gray-800 bg-gray-900/70">
              <CardHeader>
                <CardTitle className="text-cyan-300">Última operación de lab</CardTitle>
                <CardDescription>El control plane persiste start/stop como runs con timeline y estado final</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="rounded-2xl border border-gray-800 bg-black/30 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-gray-400">Run activo</span>
                    <Badge className="border-gray-700 bg-gray-800 text-cyan-300">{activeRun?.status ?? "idle"}</Badge>
                  </div>
                  <p className="mt-2 break-all font-mono text-cyan-300">{activeRunId ?? "sin run reciente"}</p>
                  <div className="mt-3 flex flex-wrap gap-3 text-gray-400">
                    <span>Labs enlazados: {activeRun?.labs?.length ?? 0}</span>
                    <span>Eventos: {activeRun?.events?.length ?? 0}</span>
                    <span>Artifacts: {activeRun?.artifacts?.length ?? 0}</span>
                  </div>
                </div>
                <Button
                  variant="outline"
                  className="w-full border-gray-700 text-gray-200 hover:bg-gray-800"
                  onClick={() => navigate("/history")}
                >
                  Abrir historial operativo
                </Button>
              </CardContent>
            </Card>

            <ScriptExecutionConsole
              script={{ name: "lab-runtime", category: "labs" }}
              isRunning={Boolean(activeRunId && !["success", "failed", "partial", "cancelled"].includes(activeRun?.status || ""))}
              runId={activeRunId}
            />
          </div>
        </section>
      </div>
    </div>
  );
};

export default Labs;
