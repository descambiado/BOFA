import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/UI/card";
import { Badge } from "@/components/UI/badge";
import { MetricCard } from "@/components/UI/MetricCard";
import { ActionButton } from "@/components/UI/ActionButton";
import { useDashboardStats } from "@/services/api";
import {
  Activity,
  CheckCircle,
  Clock,
  Cpu,
  Eye,
  HardDrive,
  Shield,
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
  const recentActivity = stats?.recent_activity ?? [];

  const quickStats = [
    {
      title: "Ejecuciones",
      value: String(executions.total_executions ?? stats?.total_executions ?? 0),
      change: `${executions.success_rate ?? stats?.completion_rate ?? 0}% éxito`,
      trend: "up" as const,
      icon: <Terminal className="w-5 h-5" />,
    },
    {
      title: "Cola Activa",
      value: String((queue.queued ?? 0) + (queue.running ?? 0)),
      change: `${queue.running ?? 0} corriendo`,
      trend: (queue.running ?? 0) > 0 ? ("up" as const) : ("down" as const),
      icon: <Activity className="w-5 h-5" />,
    },
    {
      title: "Labs Activos",
      value: String(docker.active_labs ?? stats?.active_labs ?? 0),
      change: `${docker.containers_running ?? docker.active_labs ?? 0} contenedores`,
      trend: (docker.active_labs ?? 0) > 0 ? ("up" as const) : ("down" as const),
      icon: <Eye className="w-5 h-5" />,
    },
    {
      title: "CPU",
      value: `${system.cpu_percent ?? 0}%`,
      change: (system.cpu_percent ?? 0) > 80 ? "Alta presión" : "Estable",
      trend: (system.cpu_percent ?? 0) > 80 ? ("down" as const) : ("up" as const),
      icon: <Cpu className="w-5 h-5" />,
    },
  ];

  const statusColor =
    overview.system_status === "operational"
      ? "bg-green-500/20 text-green-300 border-green-400/30"
      : "bg-yellow-500/20 text-yellow-300 border-yellow-400/30";

  return (
    <div className="relative min-h-screen p-6 animate-fade-in">
      <div className="container mx-auto max-w-7xl space-y-8">
        <section className="rounded-3xl border border-primary/20 bg-gradient-to-br from-slate-900 via-cyan-950 to-slate-950 p-8 shadow-2xl shadow-cyan-950/30">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="space-y-4">
              <Badge className={statusColor}>
                {overview.system_status ?? "unknown"}
              </Badge>
              <div>
                <h1 className="text-4xl font-bold tracking-tight text-white">BOFA Command Dashboard</h1>
                <p className="mt-2 max-w-2xl text-base text-slate-300">
                  La plataforma necesita menos marketing vacío y más telemetría accionable. Este panel ahora prioriza
                  lo que importa: ejecución real, salud del sistema, cola y actividad reciente.
                </p>
              </div>
              <div className="flex flex-wrap gap-3 text-sm text-slate-300">
                <span>Módulos: {overview.modules ?? stats?.modules ?? 0}</span>
                <span>Scripts: {overview.total_scripts ?? stats?.total_scripts ?? 0}</span>
                <span>Novedades recientes: {overview.scripts_updated_recently ?? stats?.new_scripts_2025 ?? 0}</span>
              </div>
            </div>

            <div className="grid min-w-[280px] grid-cols-2 gap-3">
              <ActionButton
                icon={<Terminal className="w-5 h-5" />}
                title="Scripts"
                description="Ejecutar herramientas"
                onClick={() => navigate("/scripts")}
              />
              <ActionButton
                icon={<Workflow className="w-5 h-5" />}
                title="Flows"
                description="Orquestar cadenas"
                onClick={() => navigate("/flows")}
              />
              <ActionButton
                icon={<Eye className="w-5 h-5" />}
                title="Labs"
                description="Entornos prácticos"
                onClick={() => navigate("/labs")}
              />
              <ActionButton
                icon={<Clock className="w-5 h-5" />}
                title="Historial"
                description="Revisar ejecuciones"
                onClick={() => navigate("/history")}
              />
              <ActionButton
                icon={<Shield className="w-5 h-5" />}
                title="Salud"
                description="Ver observabilidad"
                onClick={() => navigate("/health")}
              />
            </div>
          </div>
        </section>

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
              <CardDescription>Últimas ejecuciones registradas por la API</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {recentActivity.length === 0 && !isLoading ? (
                <div className="rounded-xl border border-dashed border-slate-700 p-6 text-sm text-slate-400">
                  No hay actividad reciente registrada todavía.
                </div>
              ) : (
                recentActivity.map((activity: any) => (
                  <div key={activity.id} className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                    <div className="min-w-0">
                      <p className="truncate font-medium text-white">
                        {activity.metadata?.script_name || activity.target || activity.requested_action || activity.run_type || "Operacion desconocida"}
                      </p>
                      <p className="text-sm text-slate-400">
                        {(activity.metadata?.module || activity.source || "runtime")} · {activity.created_at ? new Date(activity.created_at).toLocaleString() : "sin fecha"}
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
              <CardTitle className="text-cyan-300">Orquestación</CardTitle>
              <CardDescription>Capacidad real del runtime</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-sm">
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">Concurrentes máximas</span>
                <span className="font-semibold text-white">{queue.max_concurrent ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">En cola</span>
                <span className="font-semibold text-white">{queue.queued ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">En ejecución</span>
                <span className="font-semibold text-white">{queue.running ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-4">
                <span className="text-slate-400">Completadas</span>
                <span className="font-semibold text-white">{queue.completed ?? 0}</span>
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
                <span className="text-slate-400">Éxitos</span>
                <span className="text-white">{executions.successful ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Fallos</span>
                <span className="text-white">{executions.failed ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Tasa de éxito</span>
                <span className="text-white">{executions.success_rate ?? 0}%</span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-primary/20 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Sistema</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-400"><Cpu className="w-4 h-4" /> CPU</span>
                <span className="text-white">{system.cpu_percent ?? 0}%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-400"><TimerReset className="w-4 h-4" /> Memoria</span>
                <span className="text-white">{system.memory_percent ?? 0}%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-400"><HardDrive className="w-4 h-4" /> Disco libre</span>
                <span className="text-white">{system.disk_free_gb ?? 0} GB</span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-primary/20 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Infraestructura</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Labs activos</span>
                <span className="text-white">{docker.active_labs ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Contenedores</span>
                <span className="text-white">{docker.containers_running ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-400"><CheckCircle className="w-4 h-4" /> Último scan</span>
                <span className="text-white">
                  {overview.last_scan ? new Date(overview.last_scan).toLocaleString() : "n/a"}
                </span>
              </div>
            </CardContent>
          </Card>
        </section>
      </div>
    </div>
  );
};

export default Dashboard;
