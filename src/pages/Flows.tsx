import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/UI/card";
import { Badge } from "@/components/UI/badge";
import { Button } from "@/components/UI/button";
import { Input } from "@/components/UI/input";
import { ActionButton } from "@/components/UI/ActionButton";
import { ScriptExecutionConsole } from "@/components/ScriptExecutionConsole";
import { apiService, useFlows, useRunDetail, type FlowSummary } from "@/services/api";
import { ArrowRight, Clock3, GitBranch, Play, RefreshCw, Search, Workflow } from "lucide-react";
import { toast } from "sonner";

const Flows = () => {
  const navigate = useNavigate();
  const { data: flows, isLoading, refetch } = useFlows();
  const [selectedFlow, setSelectedFlow] = useState<FlowSummary | null>(null);
  const [target, setTarget] = useState("");
  const [runId, setRunId] = useState<string | null>(null);
  const [isStarting, setIsStarting] = useState(false);
  const { data: activeRun } = useRunDetail(runId);

  const featuredFlows = useMemo(() => (flows || []).slice(0, 6), [flows]);

  const handleStartFlow = async () => {
    if (!selectedFlow) {
      toast.error("Selecciona un flow");
      return;
    }
    if (!target.trim()) {
      toast.error("Define un target para ejecutar el flow");
      return;
    }

    try {
      setIsStarting(true);
      const result = await apiService.startFlow(selectedFlow.id, target.trim());
      setRunId(result.run_id);
      toast.success(result.message || `Flow ${selectedFlow.name} iniciado`);
    } catch (error) {
      toast.error("No se pudo iniciar el flow");
    } finally {
      setIsStarting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-slate-900 to-black text-white p-6">
      <div className="container mx-auto max-w-7xl space-y-8">
        <section className="rounded-3xl border border-cyan-500/20 bg-gradient-to-br from-slate-900 via-cyan-950/60 to-slate-950 p-8 shadow-2xl shadow-cyan-950/30">
          <div className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
            <div className="space-y-4">
              <Badge className="border-cyan-400/30 bg-cyan-500/20 text-cyan-200">
                Operational Flows
              </Badge>
              <div>
                <h1 className="text-4xl font-bold tracking-tight text-white">Chains, not isolated clicks</h1>
                <p className="mt-2 max-w-3xl text-base text-slate-300">
                  BOFA ya no solo ejecuta scripts sueltos. Aquí lanzamos secuencias completas con un único
                  <span className="text-cyan-300"> run_id</span>, timeline persistente y trazabilidad end-to-end.
                </p>
              </div>
              <div className="flex flex-wrap gap-3 text-sm text-slate-300">
                <span>Flows disponibles: {flows?.length ?? 0}</span>
                <span>Run activo: {runId ?? "ninguno"}</span>
                <span>Estado: {activeRun?.status ?? "idle"}</span>
              </div>
            </div>

            <div className="grid min-w-[280px] grid-cols-2 gap-3">
              <ActionButton
                icon={<RefreshCw className="w-5 h-5" />}
                title="Recargar"
                description="Refrescar catálogo"
                onClick={() => refetch()}
              />
              <ActionButton
                icon={<Clock3 className="w-5 h-5" />}
                title="Historial"
                description="Abrir runs"
                onClick={() => navigate("/history")}
              />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <Card className="border-gray-800 bg-gray-900/70">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-cyan-300">
                <Workflow className="w-5 h-5" />
                Flow Catalog
              </CardTitle>
              <CardDescription>Catálogo operativo de secuencias definidas en `config/flows`</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-2">
              {isLoading ? (
                Array.from({ length: 6 }).map((_, index) => (
                  <div key={index} className="rounded-2xl border border-gray-800 bg-black/30 p-5 animate-pulse">
                    <div className="h-5 w-1/2 rounded bg-gray-700" />
                    <div className="mt-3 h-4 w-full rounded bg-gray-800" />
                    <div className="mt-2 h-4 w-4/5 rounded bg-gray-800" />
                  </div>
                ))
              ) : (
                featuredFlows.map((flow) => (
                  <button
                    key={flow.id}
                    type="button"
                    onClick={() => setSelectedFlow(flow)}
                    className={`rounded-2xl border p-5 text-left transition-all ${
                      selectedFlow?.id === flow.id
                        ? "border-cyan-400 bg-cyan-500/10 shadow-lg shadow-cyan-950/20"
                        : "border-gray-800 bg-black/30 hover:border-cyan-500/40 hover:bg-cyan-500/5"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-lg font-semibold text-white">{flow.name}</p>
                        <p className="mt-2 text-sm text-gray-400">{flow.description || "Sin descripción"}</p>
                      </div>
                      <Badge className="border-gray-700 bg-gray-800 text-cyan-300">
                        {flow.steps_count} pasos
                      </Badge>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm text-cyan-300">
                      <GitBranch className="w-4 h-4" />
                      <span>{flow.id}</span>
                    </div>
                  </button>
                ))
              )}
            </CardContent>
          </Card>

          <div className="space-y-6">
            <Card className="border-gray-800 bg-gray-900/70">
              <CardHeader>
                <CardTitle className="text-cyan-300">Launch Flow</CardTitle>
                <CardDescription>Selecciona un flow, define target y lánzalo como run unificado</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="rounded-2xl border border-gray-800 bg-black/30 p-4">
                  <p className="text-sm text-gray-400">Flow seleccionado</p>
                  <p className="mt-1 text-lg font-semibold text-white">{selectedFlow?.name ?? "Ninguno"}</p>
                  <p className="mt-2 text-sm text-gray-500">{selectedFlow?.description ?? "Escoge un flow del catálogo para inspeccionarlo y ejecutarlo."}</p>
                </div>

                <div className="space-y-2">
                  <label htmlFor="flow-target" className="text-sm text-gray-300">
                    Target
                  </label>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                    <Input
                      id="flow-target"
                      value={target}
                      onChange={(event) => setTarget(event.target.value)}
                      placeholder="https://target.example o dominio/IP"
                      className="border-gray-700 bg-gray-950 pl-10 text-white"
                    />
                  </div>
                </div>

                <Button
                  onClick={handleStartFlow}
                  disabled={!selectedFlow || !target.trim() || isStarting}
                  className="w-full bg-cyan-600 text-white hover:bg-cyan-500"
                >
                  <Play className="mr-2 h-4 w-4" />
                  {isStarting ? "Lanzando..." : "Ejecutar flow"}
                </Button>

                {activeRun && (
                  <div className="rounded-2xl border border-gray-800 bg-black/30 p-4 text-sm">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-gray-400">Run actual</span>
                      <Badge className="border-gray-700 bg-gray-800 text-cyan-300">{activeRun.status}</Badge>
                    </div>
                    <p className="mt-2 break-all font-mono text-cyan-300">{activeRun.id}</p>
                    <div className="mt-3 flex flex-wrap gap-3 text-gray-400">
                      <span>Steps: {activeRun.steps?.length ?? 0}</span>
                      <span>Eventos: {activeRun.events?.length ?? 0}</span>
                      <span>Artifacts: {activeRun.artifacts?.length ?? 0}</span>
                    </div>
                    <Button
                      variant="outline"
                      className="mt-4 w-full border-gray-700 text-gray-200 hover:bg-gray-800"
                      onClick={() => navigate("/history")}
                    >
                      Ver detalle en historial
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            <ScriptExecutionConsole
              script={{ name: selectedFlow?.name || "flow", category: "flow" }}
              isRunning={Boolean(runId && !["success", "failed", "partial", "cancelled"].includes(activeRun?.status || ""))}
              runId={runId}
            />
          </div>
        </section>
      </div>
    </div>
  );
};

export default Flows;
