import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { MetricCard } from "@/components/ui/MetricCard";
import { ActionButton } from "@/components/ui/ActionButton";
import { useDashboardStats } from "@/services/api";
import {
  Activity,
  CheckCircle,
  Clock,
  Cpu,
  Crosshair,
  FolderSearch,
  HardDrive,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  TimerReset,
  Workflow,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

const Dashboard = () => {
  const navigate = useNavigate();
  const { data: stats, isLoading } = useDashboardStats();

  const executions = stats?.executions ?? {};
  const system = stats?.system ?? {};
  const queue = stats?.queue ?? {};
  const docker = stats?.docker ?? {};
  const overview = stats?.overview ?? {};
  const bounty = stats?.bounty ?? {};
  const recentActivity = stats?.recent_activity ?? [];

  const isDemoMode = overview.system_status === "demo";
  const statusColor = isDemoMode
    ? "bg-amber-500/20 text-amber-200 border-amber-400/30"
    : "bg-emerald-500/20 text-emerald-200 border-emerald-400/30";

  const quickStats = [
    {
      title: "Ejecuciones",
      value: String(executions.total_executions ?? stats?.total_executions ?? 0),
      change: `${executions.success_rate ?? stats?.completion_rate ?? 0}% exito`,
      trend: "up" as const,
      icon: <Terminal className="h-5 w-5" />,
    },
    {
      title: "Cola activa",
      value: String((queue.queued ?? 0) + (queue.running ?? 0)),
      change: `${queue.running ?? 0} corriendo`,
      trend: (queue.running ?? 0) > 0 ? ("up" as const) : ("down" as const),
      icon: <Activity className="h-5 w-5" />,
    },
    {
      title: "Workspaces",
      value: String(bounty.workspaces ?? 0),
      change: `${bounty.review_queue_items ?? 0} items en review queue`,
      trend: (bounty.workspaces ?? 0) > 0 ? ("up" as const) : ("down" as const),
      icon: <FolderSearch className="h-5 w-5" />,
    },
    {
      title: "Report candidates",
      value: String(bounty.report_candidates ?? 0),
      change: `${bounty.findings ?? 0} findings vivos`,
      trend: (bounty.report_candidates ?? 0) > 0 ? ("up" as const) : ("down" as const),
      icon: <ShieldAlert className="h-5 w-5" />,
    },
  ];

  return (
    <div className="relative min-h-screen p-6 animate-fade-in">
      <div className="container mx-auto max-w-7xl space-y-8">
        <section className="rounded-3xl border border-primary/20 bg-gradient-to-br from-slate-950 via-cyan-950 to-slate-950 p-8 shadow-2xl shadow-cyan-950/30">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="space-y-4">
              <Badge className={statusColor}>{overview.system_status ?? "unknown"}</Badge>
              <div>
                <h1 className="text-4xl font-bold tracking-tight text-white">BOFA Runtime Overview</h1>
                <p className="mt-2 max-w-3xl text-base text-slate-300">
                  La portada resume ejecucion real, bounty workspaces y salud del runtime desde la misma API.
                  Menos catalogo inflado y mas contexto operativo.
                </p>
              </div>
              <div className="flex flex-wrap gap-3 text-sm text-slate-300">
                <span>Modulos: {overview.modules ?? stats?.modules ?? 0}</span>
                <span>Scripts: {overview.total_scripts ?? stats?.total_scripts ?? 0}</span>
                <span>Workspaces: {bounty.workspaces ?? 0}</span>
                <span>Review queue: {bounty.review_queue_items ?? 0}</span>
              </div>
            </div>

            <div className="grid min-w-[280px] grid-cols-2 gap-3">
              <ActionButton
                icon={<Terminal className="h-5 w-5" />}
                title="Scripts"
                description="Ejecutar runtime tools"
                onClick={() => navigate("/scripts")}
              />
              <ActionButton
                icon={<Workflow className="h-5 w-5" />}
                title="Flows"
                description="Orquestar cadenas"
                onClick={() => navigate("/flows")}
              />
              <ActionButton
                icon={<Crosshair className="h-5 w-5" />}
                title="Bounty"
                description="Ver cambios y queue"
                onClick={() => navigate("/bounty")}
              />
              <ActionButton
                icon={<Shield className="h-5 w-5" />}
                title="Salud"
                description="Revisar observabilidad"
                onClick={() => navigate("/health")}
              />
              <ActionButton
                icon={<Clock className="h-5 w-5" />}
                title="Historial"
                description="Auditar ejecuciones"
                onClick={() => navigate("/history")}
              />
              <ActionButton
                icon={<Sparkles className="h-5 w-5" />}
                title="Labs"
                description="Entornos practicos"
                onClick={() => navigate("/labs")}
              />
            </div>
          </div>
        </section>

        {isDemoMode ? (
          <div className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
            La API no esta disponible en este momento. La UI muestra datos locales limitados para no fingir un runtime
            que no esta conectado.
          </div>
        ) : null}

        <section className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
          {quickStats.map((stat) => (
            <MetricCard
              key={stat.title}
              title={stat.title}
              value={stat.value}
              change={stat.change}
              trend={stat.trend}
              icon={stat.icon}
            />
          ))}
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <Card className="border-primary/20 bg-slate-900/80 xl:col-span-2">
            <CardHeader>
              <CardTitle className="text-cyan-300">Actividad reciente</CardTitle>
              <CardDescription>Ultimas ejecuciones registradas por la API</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {recentActivity.length === 0 && !isLoading ? (
                <div className="rounded-xl border border-dashed border-slate-700 p-6 text-sm text-slate-400">
                  No hay actividad reciente registrada todavia.
                </div>
              ) : (
                recentActivity.map((activity: any) => (
                  <div
                    key={activity.id}
                    className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/70 p-4"
                  >
                    <div className="min-w-0">
                      <p className="truncate font-medium text-white">
                        {activity.metadata?.script_name ||
                          activity.target ||
                          activity.requested_action ||
                          activity.run_type ||
                          "Operacion desconocida"}
                      </p>
                      <p className="text-sm text-slate-400">
                        {(activity.metadata?.module || activity.source || "runtime")} ·{" "}
                        {activity.created_at ? new Date(activity.created_at).toLocaleString() : "sin fecha"}
                      </p>
                    </div>
                    <Badge
                      className={
                        activity.status === "success"
                          ? "bg-green-500/20 text-green-300 border-green-400/30"
                          : activity.status === "running"
                            ? "bg-blue-500/20 text-blue-300 border-blue-400/30"
                            : "bg-yellow-500/20 text-yellow-300 border-yellow-400/30"
                      }
                    >
                      {activity.status ?? "unknown"}
                    </Badge>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          <Card className="border-primary/20 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Runtime queue</CardTitle>
              <CardDescription>Capacidad real del motor local</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-sm">
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">Concurrentes maximas</span>
                <span className="font-semibold text-white">{queue.max_concurrent ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">En cola</span>
                <span className="font-semibold text-white">{queue.queued ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">En ejecucion</span>
                <span className="font-semibold text-white">{queue.running ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">Completadas</span>
                <span className="font-semibold text-white">{queue.completed ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">Labs activos</span>
                <span className="font-semibold text-white">{docker.active_labs ?? stats?.active_labs ?? 0}</span>
              </div>
            </CardContent>
          </Card>
        </section>

        <section className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <Card className="border-primary/20 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Fiabilidad</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Exitos</span>
                <span className="text-white">{executions.successful ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Fallos</span>
                <span className="text-white">{executions.failed ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Tasa de exito</span>
                <span className="text-white">{executions.success_rate ?? 0}%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Threat level</span>
                <span className="text-white">{overview.threat_level ?? stats?.threat_level ?? "unknown"}</span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-primary/20 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Sistema</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-400">
                  <Cpu className="h-4 w-4" />
                  CPU
                </span>
                <span className="text-white">{system.cpu_percent ?? 0}%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-400">
                  <TimerReset className="h-4 w-4" />
                  Memoria
                </span>
                <span className="text-white">{system.memory_percent ?? 0}%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-400">
                  <HardDrive className="h-4 w-4" />
                  Disco libre
                </span>
                <span className="text-white">{system.disk_free_gb ?? 0} GB</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-400">
                  <CheckCircle className="h-4 w-4" />
                  Ultimo scan
                </span>
                <span className="text-white">
                  {overview.last_scan ? new Date(overview.last_scan).toLocaleString() : "n/a"}
                </span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-primary/20 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Bounty signal</CardTitle>
              <CardDescription>Lo que hace util al workflow duplicate-aware</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Workspaces activos</span>
                <span className="text-white">{bounty.active_workspaces ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Snapshots</span>
                <span className="text-white">{bounty.snapshots ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Findings vivos</span>
                <span className="text-white">{bounty.findings ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Review queue</span>
                <span className="text-white">{bounty.review_queue_items ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Report candidates</span>
                <span className="text-white">{bounty.report_candidates ?? 0}</span>
              </div>
              <div className="rounded-xl bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">Ultimo workspace</p>
                <p className="mt-2 font-medium text-white">{bounty.latest_workspace_name ?? "Sin workspaces"}</p>
                <p className="mt-1 text-xs text-slate-400">{bounty.latest_program_handle ?? "sin programa"}</p>
              </div>
            </CardContent>
          </Card>
        </section>
      </div>
    </div>
  );
};

export default Dashboard;
