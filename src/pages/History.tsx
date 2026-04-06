import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ActionButton } from "@/components/UI/ActionButton";
import { useRunDetail, useRuns, apiService } from "@/services/api";
import { ArrowLeft, Clock, Download, Eye, RefreshCw, RotateCcw, Square } from "lucide-react";
import { toast } from "sonner";

const History = () => {
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const { data: runs, isLoading, refetch } = useRuns();
  const { data: selectedRun, refetch: refetchRun } = useRunDetail(selectedRunId);
  const isFinalStatus = (status?: string) => ["success", "failed", "error", "partial", "cancelled"].includes(status || "");

  const formatTimestamp = (timestamp?: string) => (timestamp ? new Date(timestamp).toLocaleString("es-ES") : "sin fecha");

  const downloadRun = (run: any) => {
    const content = JSON.stringify(run, null, 2);
    const blob = new Blob([content], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bofa-run-${run.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCancel = async (runId: string) => {
    try {
      await apiService.cancelRun(runId);
      toast.success("Run cancelado");
      refetch();
      if (selectedRunId === runId) refetchRun();
    } catch (error) {
      toast.error("No se pudo cancelar el run");
    }
  };

  const handleRetry = async (runId: string) => {
    try {
      await apiService.retryRun(runId);
      toast.success("Run reintentado");
      refetch();
    } catch (error) {
      toast.error("No se pudo reintentar el run");
    }
  };

  if (selectedRun && selectedRunId) {
    return (
      <div className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center justify-between">
          <ActionButton icon={<ArrowLeft className="w-4 h-4" />} title="Volver" description="Volver al historial" onClick={() => setSelectedRunId(null)} />
          <div className="flex gap-3">
            <Button variant="outline" disabled={!isFinalStatus(selectedRun.status)} onClick={() => handleRetry(selectedRun.id)} className="border-gray-600 text-gray-300 hover:bg-gray-700 disabled:opacity-50">
              <RotateCcw className="mr-2 h-4 w-4" /> Reintentar
            </Button>
            <Button variant="outline" disabled={isFinalStatus(selectedRun.status) || selectedRun.status === "cancelling"} onClick={() => handleCancel(selectedRun.id)} className="border-red-500/40 text-red-300 hover:bg-red-500/10 disabled:opacity-50">
              <Square className="mr-2 h-4 w-4" /> Cancelar
            </Button>
          </div>
        </div>

        <div className="grid gap-6">
          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="text-cyan-400 flex items-center justify-between">
                <span>Run {selectedRun.id}</span>
                <Badge>{selectedRun.status === "cancelling" ? "cancel requested" : selectedRun.status}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-4">
              <div><span className="text-gray-400 text-sm block">Tipo</span><span className="text-white">{selectedRun.run_type}</span></div>
              <div><span className="text-gray-400 text-sm block">Acción</span><span className="text-white">{selectedRun.requested_action}</span></div>
              <div><span className="text-gray-400 text-sm block">Creado</span><span className="text-white">{formatTimestamp(selectedRun.created_at)}</span></div>
              <div><span className="text-gray-400 text-sm block">Target</span><span className="text-white">{selectedRun.target || "n/a"}</span></div>
            </CardContent>
          </Card>

          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="text-cyan-400">Steps</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedRun.steps?.length ? selectedRun.steps.map((step) => (
                <div key={step.id} className="rounded-lg border border-gray-700 bg-gray-900/60 p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium text-white">{step.module || step.step_type} / {step.script_name || step.step_key || step.id}</p>
                      <p className="text-sm text-gray-400">Inicio: {formatTimestamp(step.started_at)} · Fin: {formatTimestamp(step.completed_at)}</p>
                    </div>
                    <Badge>{step.status === "cancelling" ? "cancel requested" : step.status}</Badge>
                  </div>
                  {(step.stdout_preview || step.error_message) && (
                    <pre className="mt-3 whitespace-pre-wrap rounded bg-black p-3 text-sm text-gray-300">
                      {step.stdout_preview || step.error_message}
                    </pre>
                  )}
                </div>
              )) : <p className="text-gray-400">Sin steps registrados.</p>}
            </CardContent>
          </Card>

          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="text-cyan-400">Timeline</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedRun.events?.length ? selectedRun.events.map((event) => (
                <div key={event.id} className="rounded-lg border border-gray-700 bg-gray-900/60 p-4">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-white">{event.scope_type} · {event.event_type}</span>
                    <Badge>{event.status === "cancelling" ? "cancel requested" : event.status || "info"}</Badge>
                  </div>
                  <p className="mt-2 text-sm text-gray-300">{event.message || "Sin mensaje"}</p>
                  <p className="mt-1 text-xs text-gray-500">{formatTimestamp(event.created_at)}</p>
                </div>
              )) : <p className="text-gray-400">Sin eventos registrados.</p>}
            </CardContent>
          </Card>

          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="text-cyan-400 flex items-center justify-between">
                <span>Artifacts</span>
                <ActionButton icon={<Download className="w-4 h-4" />} title="Exportar" description="Descargar run" onClick={() => downloadRun(selectedRun)} />
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedRun.artifacts?.length ? selectedRun.artifacts.map((artifact) => (
                <div key={artifact.id} className="rounded-lg border border-gray-700 bg-gray-900/60 p-4">
                  <p className="font-medium text-white">{artifact.label || artifact.artifact_type}</p>
                  <p className="mt-1 break-all text-sm text-gray-400">{artifact.path}</p>
                </div>
              )) : <p className="text-gray-400">Sin artifacts registrados.</p>}
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-6 py-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-cyan-400 mb-2">Historial Operativo</h1>
          <p className="text-gray-300">Runs unificados con trazabilidad end-to-end</p>
        </div>
        <ActionButton icon={<RefreshCw className="w-4 h-4" />} title="Actualizar" description="Refrescar runs" onClick={() => refetch()} />
      </div>

      {isLoading ? (
        <div className="text-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto"></div>
          <p className="text-gray-400 mt-4">Cargando runs...</p>
        </div>
      ) : !runs?.length ? (
        <Card className="bg-gray-800/50 border-gray-700">
          <CardContent className="text-center py-12">
            <Clock className="w-12 h-12 text-gray-500 mx-auto mb-4" />
            <h3 className="text-xl text-gray-400 mb-2">Sin runs registrados</h3>
            <p className="text-gray-500">Ejecuta scripts, flows o labs para verlos aquí</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {runs.map((run) => (
            <Card key={run.id} className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all cursor-pointer" onClick={() => setSelectedRunId(run.id)}>
              <CardContent className="p-6">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h3 className="text-lg font-semibold text-white">{run.metadata?.script || run.target || run.requested_action}</h3>
                    <p className="text-sm text-gray-400">{formatTimestamp(run.created_at)}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge>{run.run_type}</Badge>
                    <Badge>{run.status === "cancelling" ? "cancel requested" : run.status}</Badge>
                    <ActionButton icon={<Eye className="w-4 h-4" />} title="Ver" description="Ver detalle" onClick={() => setSelectedRunId(run.id)} />
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-4 text-sm text-gray-400">
                  <span>Acción: <span className="text-cyan-400">{run.requested_action}</span></span>
                  <span>Steps: {run.step_count ?? 0}</span>
                  <span>Eventos: {run.timeline_count ?? 0}</span>
                  <span>Artifacts: {run.artifact_count ?? 0}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

export default History;
