import { useEffect, useState } from "react";
import {
  Bot,
  CheckCircle2,
  Cloud,
  Cpu,
  Fingerprint,
  LockKeyhole,
  RefreshCw,
  Server,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AIProviders,
  ExecutionCapabilities,
  ExecutionProfile,
  ExecutionTrust,
  apiService,
} from "@/services/api";

const backendCopy: Record<ExecutionProfile["backend"], { label: string; icon: typeof Cpu }> = {
  local: { label: "Runtime local", icon: Cpu },
  oci: { label: "Contenedor efimero", icon: Server },
  remote: { label: "Worker cloud", icon: Cloud },
};

function ProfileCard({ profile }: { profile: ExecutionProfile }) {
  const backend = backendCopy[profile.backend];
  const BackendIcon = backend.icon;
  const outputMb = Math.round(profile.limits.max_output_bytes / (1024 * 1024));

  return (
    <Card className="overflow-hidden border-slate-700/70 bg-slate-950/70">
      <div className={`h-1 ${profile.enabled ? "bg-emerald-400" : "bg-amber-400"}`} />
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-3">
              <BackendIcon className="h-5 w-5 text-cyan-300" />
            </div>
            <div>
              <CardTitle className="text-lg text-white">{backend.label}</CardTitle>
              <CardDescription className="font-mono text-xs">{profile.id}</CardDescription>
            </div>
          </div>
          <Badge
            className={
              profile.enabled
                ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-200"
                : "border-amber-400/30 bg-amber-400/10 text-amber-200"
            }
          >
            {profile.enabled ? "Disponible" : "Sin configurar"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid grid-cols-3 gap-3 text-sm">
          <div className="rounded-xl bg-slate-900/80 p-3">
            <p className="text-xs text-slate-500">TTL max.</p>
            <p className="mt-1 font-semibold text-slate-100">{profile.limits.max_duration_seconds}s</p>
          </div>
          <div className="rounded-xl bg-slate-900/80 p-3">
            <p className="text-xs text-slate-500">Memoria</p>
            <p className="mt-1 font-semibold text-slate-100">{profile.limits.memory_mb} MB</p>
          </div>
          <div className="rounded-xl bg-slate-900/80 p-3">
            <p className="text-xs text-slate-500">Salida</p>
            <p className="mt-1 font-semibold text-slate-100">{outputMb} MB</p>
          </div>
        </div>

        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
            Capacidades permitidas
          </p>
          <div className="flex flex-wrap gap-2">
            {profile.capabilities.map((capability) => (
              <Badge key={capability} variant="outline" className="border-slate-700 text-slate-300">
                {capability}
              </Badge>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-800 pt-4 text-xs">
          <span className="text-slate-400">
            Red: <strong className="text-slate-200">{profile.network_mode}</strong>
          </span>
          <span className="text-slate-400">
            {profile.ephemeral ? "Destruccion obligatoria" : "Persistente"}
          </span>
        </div>

        {!profile.enabled && profile.availability_reason ? (
          <p className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-3 text-xs leading-5 text-amber-100">
            {profile.availability_reason}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

const Fabric = () => {
  const [capabilities, setCapabilities] = useState<ExecutionCapabilities | null>(null);
  const [trust, setTrust] = useState<ExecutionTrust | null>(null);
  const [ai, setAI] = useState<AIProviders | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [capabilityData, trustData, aiData] = await Promise.all([
        apiService.getExecutionCapabilities(),
        apiService.getExecutionTrust(),
        apiService.getAIProviders(),
      ]);
      setCapabilities(capabilityData);
      setTrust(trustData);
      setAI(aiData);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Execution fabric no disponible");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  return (
    <div className="container relative mx-auto max-w-7xl px-6 py-10">
      <section className="relative mb-10 overflow-hidden rounded-[2rem] border border-cyan-400/20 bg-slate-950/80 p-7 md:p-10">
        <div className="pointer-events-none absolute -right-24 -top-32 h-80 w-80 rounded-full bg-cyan-400/10 blur-3xl" />
        <div className="relative flex flex-col gap-7 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-3xl">
            <div className="mb-5 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.24em] text-cyan-300">
              <ShieldCheck className="h-4 w-4" />
              Execution Fabric v3
            </div>
            <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
              La autorizacion viaja con cada run.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-300">
              BOFA une alcance escrito, limites, aprobacion humana, ejecucion efimera y evidencia firmada.
              Una VM no recibe autoridad general: recibe un trabajo verificable y de un solo uso.
            </p>
          </div>
          <Button onClick={load} disabled={loading} className="bg-cyan-500 text-slate-950 hover:bg-cyan-300">
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Revalidar fabric
          </Button>
        </div>
      </section>

      {error ? (
        <Card className="mb-8 border-red-400/30 bg-red-950/30">
          <CardContent className="flex items-center gap-3 p-5 text-red-100">
            <TriangleAlert className="h-5 w-5 shrink-0" />
            {error}
          </CardContent>
        </Card>
      ) : null}

      <div className="mb-10 grid gap-5 md:grid-cols-3">
        <Card className="border-emerald-400/20 bg-emerald-400/5">
          <CardContent className="flex gap-4 p-6">
            <LockKeyhole className="mt-1 h-6 w-6 shrink-0 text-emerald-300" />
            <div>
              <p className="font-semibold text-white">Deny by default</p>
              <p className="mt-1 text-sm leading-6 text-slate-400">Sin grant, scope y preflight no existe ejecucion.</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-cyan-400/20 bg-cyan-400/5">
          <CardContent className="flex gap-4 p-6">
            <Fingerprint className="mt-1 h-6 w-6 shrink-0 text-cyan-300" />
            <div>
              <p className="font-semibold text-white">{trust?.algorithm ?? "Firma no cargada"}</p>
              <p className="mt-1 break-all font-mono text-xs leading-5 text-slate-400">
                {trust?.key_id ?? "Esperando raiz de confianza"}
              </p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-sky-400/20 bg-sky-400/5">
          <CardContent className="flex gap-4 p-6">
            <Bot className="mt-1 h-6 w-6 shrink-0 text-sky-300" />
            <div>
              <p className="font-semibold text-white">IA sin autoridad operativa</p>
              <p className="mt-1 text-sm leading-6 text-slate-400">Planifica y explica; la policy decide cada accion.</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <section className="mb-12">
        <div className="mb-5 flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-cyan-300">Runners</p>
            <h2 className="mt-2 text-2xl font-bold text-white">Donde puede ejecutarse BOFA</h2>
          </div>
          <p className="text-sm text-slate-500">Policy {capabilities?.policy_version ?? "sin conectar"}</p>
        </div>
        <div className="grid gap-5 lg:grid-cols-3">
          {capabilities?.profiles.map((profile) => <ProfileCard key={profile.id} profile={profile} />)}
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1.25fr_0.75fr]">
        <Card className="border-slate-700/70 bg-slate-950/70">
          <CardHeader>
            <CardTitle className="text-white">Proveedores LLM</CardTitle>
            <CardDescription>Local-first por defecto; los proveedores remotos requieren consentimiento por run.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {ai?.providers.map((provider) => (
              <div
                key={provider.id}
                className="grid gap-3 rounded-2xl border border-slate-800 bg-slate-900/60 p-4 md:grid-cols-[1fr_auto] md:items-center"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-semibold text-white">{provider.id}</p>
                    <Badge variant="outline" className="border-slate-700 text-slate-300">
                      {provider.locality}
                    </Badge>
                    {provider.id === ai.default ? (
                      <Badge className="bg-cyan-400/10 text-cyan-200">default</Badge>
                    ) : null}
                  </div>
                  <p className="mt-1 truncate text-xs text-slate-500">{provider.model} · {provider.endpoint}</p>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  {provider.configured ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-300" />
                  ) : (
                    <TriangleAlert className="h-4 w-4 text-amber-300" />
                  )}
                  <span className={provider.transmits_workspace_data ? "text-amber-200" : "text-emerald-200"}>
                    {provider.transmits_workspace_data ? "Envia datos fuera" : "Datos locales"}
                  </span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="border-slate-700/70 bg-slate-950/70">
          <CardHeader>
            <CardTitle className="text-white">Invariantes</CardTitle>
            <CardDescription>Reglas que un adaptador cloud no puede debilitar.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            {[
              "Scope explicito y sin comodines",
              "Aprobacion humana vinculada al grant",
              "Imagen remota fijada por digest",
              "Workers efimeros y red restringida",
              "Privilegios y mutaciones cloud bloqueados",
            ].map((rule) => (
              <div key={rule} className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" />
                <span className="text-slate-300">{rule}</span>
              </div>
            ))}
            {capabilities?.blocked_capabilities.length ? (
              <div className="mt-5 rounded-xl border border-red-400/20 bg-red-400/5 p-4">
                <p className="text-xs font-semibold uppercase tracking-wider text-red-200">Siempre bloqueado</p>
                <p className="mt-2 font-mono text-xs text-red-100">
                  {capabilities.blocked_capabilities.join(" · ")}
                </p>
              </div>
            ) : null}
          </CardContent>
        </Card>
      </section>
    </div>
  );
};

export default Fabric;
