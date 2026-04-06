import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RefreshCw, CheckCircle, AlertCircle, XCircle, Activity } from "lucide-react";
import { APP_CONFIG } from "@/config/app";

type ServiceHealth = {
  service: string;
  status: "healthy" | "warning" | "error" | "offline";
  details?: string;
  responseTime?: number;
  timestamp: string;
  stats?: Record<string, unknown>;
};

type OverallHealth = {
  status: string;
  services?: Record<string, string>;
  system?: {
    cpu_usage?: number;
    memory_usage?: number;
    active_executions?: number;
    disk_free_gb?: number;
  };
  queue?: {
    queued?: number;
    running?: number;
    completed?: number;
    max_concurrent?: number;
  };
  timestamp: string;
};

const serviceEndpoints = [
  { name: "API Core", path: "/health" },
  { name: "Database", path: "/health/database" },
  { name: "Script Executor", path: "/health/scripts" },
  { name: "Lab Manager", path: "/health/labs" },
  { name: "Execution Queue", path: "/health/queue" },
];

const Health = () => {
  const [overall, setOverall] = useState<OverallHealth | null>(null);
  const [services, setServices] = useState<ServiceHealth[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadHealth = async () => {
    setIsLoading(true);

    const results = await Promise.all(
      serviceEndpoints.map(async ({ name, path }) => {
        const start = performance.now();
        try {
          const response = await fetch(`${APP_CONFIG.api.baseUrl}${path}`, {
            signal: AbortSignal.timeout(5000),
          });
          const elapsed = Math.round(performance.now() - start);

          if (!response.ok) {
            return {
              service: name,
              status: "offline" as const,
              details: `HTTP ${response.status}`,
              responseTime: elapsed,
              timestamp: new Date().toISOString(),
            };
          }

          const payload = await response.json();
          if (path === "/health") {
            setOverall(payload);
          }

          return {
            service: name,
            status: payload.status ?? "healthy",
            details: payload.details ?? payload.edition ?? "Servicio operativo",
            responseTime: elapsed,
            timestamp: payload.timestamp ?? new Date().toISOString(),
            stats: payload.stats ?? payload.system ?? payload.queue,
          };
        } catch (error) {
          return {
            service: name,
            status: "offline" as const,
            details: error instanceof Error ? error.message : "No disponible",
            timestamp: new Date().toISOString(),
          };
        }
      })
    );

    setServices(results);
    setIsLoading(false);
  };

  useEffect(() => {
    loadHealth();
    const interval = setInterval(loadHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const iconForStatus = (status: ServiceHealth["status"]) => {
    if (status === "healthy") return <CheckCircle className="w-5 h-5 text-green-400" />;
    if (status === "warning") return <AlertCircle className="w-5 h-5 text-yellow-400" />;
    return <XCircle className="w-5 h-5 text-red-400" />;
  };

  const badgeClass = (status: ServiceHealth["status"]) => {
    if (status === "healthy") return "bg-green-500/20 text-green-300 border-green-400/30";
    if (status === "warning") return "bg-yellow-500/20 text-yellow-300 border-yellow-400/30";
    return "bg-red-500/20 text-red-300 border-red-400/30";
  };

  return (
    <div className="container mx-auto max-w-7xl px-6 py-8">
      <div className="mb-8 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Health & Observability</h1>
          <p className="mt-2 text-slate-400">
            Estado real de servicios, cola y recursos del sistema para BOFA v{APP_CONFIG.version}.
          </p>
        </div>
        <Button onClick={loadHealth} disabled={isLoading} className="bg-cyan-600 hover:bg-cyan-700">
          <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          Actualizar
        </Button>
      </div>

      <div className="mb-8 grid grid-cols-1 gap-6 lg:grid-cols-4">
        <Card className="border-primary/20 bg-slate-900/80 lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-cyan-300">Resumen global</CardTitle>
            <CardDescription>Visión agregada del backend</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
            <div>
              <p className="text-slate-400">Estado</p>
              <p className="font-semibold text-white">{overall?.status ?? "unknown"}</p>
            </div>
            <div>
              <p className="text-slate-400">CPU</p>
              <p className="font-semibold text-white">{overall?.system?.cpu_usage ?? 0}%</p>
            </div>
            <div>
              <p className="text-slate-400">Memoria</p>
              <p className="font-semibold text-white">{overall?.system?.memory_usage ?? 0}%</p>
            </div>
            <div>
              <p className="text-slate-400">Ejecuciones activas</p>
              <p className="font-semibold text-white">{overall?.system?.active_executions ?? 0}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-slate-900/80">
          <CardHeader>
            <CardTitle className="text-cyan-300">Cola</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-slate-400">Queued</span><span className="text-white">{overall?.queue?.queued ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Running</span><span className="text-white">{overall?.queue?.running ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Completed</span><span className="text-white">{overall?.queue?.completed ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Max concurrent</span><span className="text-white">{overall?.queue?.max_concurrent ?? 0}</span></div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-slate-900/80">
          <CardHeader>
            <CardTitle className="text-cyan-300">Timestamp</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-white">
            {overall?.timestamp ? new Date(overall.timestamp).toLocaleString() : "sin datos"}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6">
        {services.map((service) => (
          <Card key={service.service} className="border-primary/20 bg-slate-900/80">
            <CardHeader>
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div className="flex items-center gap-3">
                  {iconForStatus(service.status)}
                  <CardTitle className="text-white">{service.service}</CardTitle>
                </div>
                <Badge className={badgeClass(service.status)}>{service.status}</Badge>
              </div>
            </CardHeader>
            <CardContent className="grid gap-4 text-sm md:grid-cols-4">
              <div>
                <p className="text-slate-400">Detalle</p>
                <p className="text-white">{service.details ?? "Sin detalle"}</p>
              </div>
              <div>
                <p className="text-slate-400">Última verificación</p>
                <p className="text-white">{new Date(service.timestamp).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-slate-400">Latencia</p>
                <p className="text-white">{service.responseTime ?? 0} ms</p>
              </div>
              <div>
                <p className="text-slate-400">Datos</p>
                <p className="break-words text-white">
                  {service.stats ? JSON.stringify(service.stats) : "Sin métricas adicionales"}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {!services.length && !isLoading && (
        <Card className="mt-6 border-primary/20 bg-slate-900/80">
          <CardContent className="flex items-center gap-3 p-6 text-slate-400">
            <Activity className="h-5 w-5" />
            No se pudieron cargar métricas del sistema.
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default Health;
