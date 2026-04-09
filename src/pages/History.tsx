import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ActionButton } from "@/components/UI/ActionButton";
import { useRunDetail, useRuns, apiService, type RunArtifact, type RunArtifactPreview, type RunSummary } from "@/services/api";
import { ArrowLeft, Clock, Copy, Download, Eye, Filter, RefreshCw, RotateCcw, Search, Square, Workflow } from "lucide-react";
import { toast } from "sonner";

const FINAL_STATUSES = ["success", "failed", "error", "partial", "cancelled"];

const getDisplayStatus = (status?: string) => (status === "cancelling" ? "cancel requested" : status || "unknown");
const getRootFamilyId = (run: RunSummary) => run.parent_run_id || run.metadata?.retry_of || run.id;

const History = () => {
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [familyFilter, setFamilyFilter] = useState("all");
  const [artifactPreview, setArtifactPreview] = useState<RunArtifactPreview | null>(null);
  const [artifactPreviewId, setArtifactPreviewId] = useState<string | null>(null);
  const [isArtifactPreviewLoading, setIsArtifactPreviewLoading] = useState(false);
  const [isExportingRun, setIsExportingRun] = useState(false);
  const { data: runs, isLoading, refetch } = useRuns();
  const { data: selectedRun, refetch: refetchRun } = useRunDetail(selectedRunId);

  const isFinalStatus = (status?: string) => FINAL_STATUSES.includes(status || "");
  const formatTimestamp = (timestamp?: string) => (timestamp ? new Date(timestamp).toLocaleString("es-ES") : "sin fecha");
  const formatBytes = (value?: number) => {
    if (!value && value !== 0) return "tamano n/a";
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  };

  useEffect(() => {
    setArtifactPreview(null);
    setArtifactPreviewId(null);
    setIsArtifactPreviewLoading(false);
  }, [selectedRunId]);

  const families = useMemo(() => {
    const grouped = new Map<string, RunSummary[]>();
    for (const run of runs || []) {
      const familyId = getRootFamilyId(run);
      const current = grouped.get(familyId) || [];
      current.push(run);
      grouped.set(familyId, current);
    }
    return grouped;
  }, [runs]);

  const filteredRuns = useMemo(() => {
    return (runs || []).filter((run) => {
      const label = `${run.metadata?.script || ""} ${run.metadata?.flow_id || ""} ${run.target || ""} ${run.requested_action || ""} ${run.run_type || ""}`.toLowerCase();
      const matchesSearch = !searchTerm.trim() || label.includes(searchTerm.trim().toLowerCase());
      const matchesStatus = statusFilter === "all" || run.status === statusFilter;
      const matchesType = typeFilter === "all" || run.run_type === typeFilter;
      const matchesFamily = familyFilter === "all" || getRootFamilyId(run) === familyFilter;
      return matchesSearch && matchesStatus && matchesType && matchesFamily;
    });
  }, [runs, searchTerm, statusFilter, typeFilter, familyFilter]);

  const selectedFamilyRuns = useMemo(() => {
    if (!selectedRun) return [];
    const familyId = getRootFamilyId(selectedRun);
    return (families.get(familyId) || []).sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  }, [selectedRun, families]);

  const copyArtifactPath = async (path: string) => {
    try {
      await navigator.clipboard.writeText(path);
      toast.success("Ruta copiada");
    } catch {
      toast.error("No se pudo copiar la ruta");
    }
  };

  const handleExport = async (runId: string) => {
    setIsExportingRun(true);
    try {
      const result = await apiService.downloadRunExport(runId);
      toast.success(result.demo ? `Export demo descargado: ${result.filename}` : `Evidence bundle descargado: ${result.filename}`);
      await refetch();
      if (selectedRunId === runId) {
        await refetchRun();
      }
    } catch {
      toast.error("No se pudo exportar el bundle del run");
    } finally {
      setIsExportingRun(false);
    }
  };

  const handleArtifactPreview = async (artifact: RunArtifact) => {
    if (!selectedRunId) return;
    if (artifactPreviewId === artifact.id) {
      setArtifactPreview(null);
      setArtifactPreviewId(null);
      return;
    }

    setIsArtifactPreviewLoading(true);
    try {
      const preview = await apiService.getRunArtifactPreview(selectedRunId, artifact.id);
      setArtifactPreview(preview);
      setArtifactPreviewId(artifact.id);
      if (!preview.previewable && preview.reason) {
        toast.info(`Preview no disponible: ${preview.reason}`);
      }
    } catch {
      toast.error("No se pudo cargar el preview del artifact");
    } finally {
      setIsArtifactPreviewLoading(false);
    }
  };

  const handleCancel = async (runId: string) => {
    try {
      const result = await apiService.cancelRun(runId);
      toast.success(result.message || "Run cancelado");
      refetch();
      if (selectedRunId === runId) refetchRun();
    } catch {
      toast.error("No se pudo cancelar el run");
    }
  };

  const handleRetry = async (runId: string) => {
    try {
      const result = await apiService.retryRun(runId);
      toast.success(result.message || "Run reintentado");
      refetch();
      if (result.run_id) {
        setSelectedRunId(result.run_id);
      }
    } catch {
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
                <Badge>{getDisplayStatus(selectedRun.status)}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
              <div><span className="text-gray-400 text-sm block">Tipo</span><span className="text-white">{selectedRun.run_type}</span></div>
              <div><span className="text-gray-400 text-sm block">Acción</span><span className="text-white">{selectedRun.requested_action}</span></div>
              <div><span className="text-gray-400 text-sm block">Creado</span><span className="text-white">{formatTimestamp(selectedRun.created_at)}</span></div>
              <div><span className="text-gray-400 text-sm block">Target</span><span className="text-white">{selectedRun.target || "n/a"}</span></div>
              <div><span className="text-gray-400 text-sm block">Retry of</span><span className="text-white break-all">{selectedRun.parent_run_id || selectedRun.metadata?.retry_of || "n/a"}</span></div>
              <div><span className="text-gray-400 text-sm block">Retry count</span><span className="text-white">{selectedRun.metadata?.retry_count ?? 0}</span></div>
            </CardContent>
          </Card>

          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="text-cyan-400 flex items-center gap-2">
                <Workflow className="h-5 w-5" />
                Familia de ejecución
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedFamilyRuns.length ? selectedFamilyRuns.map((run) => (
                <button
                  key={run.id}
                  type="button"
                  onClick={() => setSelectedRunId(run.id)}
                  className={`w-full rounded-lg border p-4 text-left transition-all ${
                    run.id === selectedRun.id ? "border-cyan-400 bg-cyan-500/10" : "border-gray-700 bg-gray-900/60 hover:border-cyan-500/40"
                  }`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="font-medium text-white">{run.metadata?.script || run.metadata?.flow_id || run.target || run.requested_action}</p>
                      <p className="text-sm text-gray-400">{formatTimestamp(run.created_at)}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge>{run.run_type}</Badge>
                      <Badge>{getDisplayStatus(run.status)}</Badge>
                    </div>
                  </div>
                </button>
              )) : <p className="text-gray-400">Sin runs relacionados.</p>}
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
                    <Badge>{getDisplayStatus(step.status)}</Badge>
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

          <div className="grid gap-6 xl:grid-cols-2">
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-cyan-400">Timeline</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {selectedRun.events?.length ? selectedRun.events.map((event) => (
                  <div key={event.id} className="rounded-lg border border-gray-700 bg-gray-900/60 p-4">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-white">{event.scope_type} · {event.event_type}</span>
                      <Badge>{getDisplayStatus(event.status)}</Badge>
                    </div>
                    <p className="mt-2 text-sm text-gray-300">{event.message || "Sin mensaje"}</p>
                    {!!Object.keys(event.payload || {}).length && (
                      <pre className="mt-3 whitespace-pre-wrap rounded bg-black/70 p-3 text-xs text-cyan-100">
                        {JSON.stringify(event.payload, null, 2)}
                      </pre>
                    )}
                    <p className="mt-1 text-xs text-gray-500">{formatTimestamp(event.created_at)}</p>
                  </div>
                )) : <p className="text-gray-400">Sin eventos registrados.</p>}
              </CardContent>
            </Card>

            <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="text-cyan-400 flex items-center justify-between">
                  <span>Artifacts</span>
                  <Button
                    variant="outline"
                    disabled={isExportingRun}
                    onClick={() => handleExport(selectedRun.id)}
                    className="border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    {isExportingRun ? "Exportando..." : "Exportar bundle"}
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {selectedRun.artifacts?.length ? selectedRun.artifacts.map((artifact) => (
                  <div key={artifact.id} className="rounded-lg border border-gray-700 bg-gray-900/60 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="font-medium text-white">{artifact.label || artifact.artifact_type}</p>
                        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                          <Badge>{artifact.artifact_type}</Badge>
                          {artifact.metadata?.step_status && <Badge>{getDisplayStatus(artifact.metadata.step_status)}</Badge>}
                          {artifact.metadata?.partial && <Badge className="bg-amber-500/20 text-amber-200">evidence partial</Badge>}
                        </div>
                        <p className="mt-2 text-xs text-gray-400">
                          {artifact.metadata?.artifact_role || "evidence"} · {artifact.metadata?.content_type || "content-type n/a"} · {formatBytes(artifact.metadata?.size_bytes)}
                        </p>
                        <p className="mt-1 break-all text-sm text-gray-400">{artifact.path}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        {artifact.metadata?.previewable && (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={isArtifactPreviewLoading && artifactPreviewId === artifact.id}
                            onClick={() => handleArtifactPreview(artifact)}
                            className="border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                        )}
                        <Button size="sm" variant="outline" onClick={() => copyArtifactPath(artifact.path)} className="border-gray-600 text-gray-300 hover:bg-gray-700">
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                )) : <p className="text-gray-400">Sin artifacts registrados.</p>}
                {artifactPreview && (
                  <div className="rounded-lg border border-cyan-500/30 bg-black/60 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-medium text-white">{artifactPreview.artifact.label || artifactPreview.artifact.artifact_type}</p>
                      <Badge>{artifactPreview.preview_mode || "preview"}</Badge>
                      {artifactPreview.artifact.metadata?.partial && (
                        <Badge className="bg-amber-500/20 text-amber-200">
                          {selectedRun.status === "cancelled" ? "cancelled evidence" : "partial evidence"}
                        </Badge>
                      )}
                    </div>
                    <p className="mt-2 text-xs text-gray-400">
                      {artifactPreview.content_type || artifactPreview.artifact.metadata?.content_type || "content-type n/a"} · {formatBytes(artifactPreview.size_bytes || artifactPreview.artifact.metadata?.size_bytes)}
                    </p>
                    {artifactPreview.previewable && artifactPreview.preview ? (
                      <>
                        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap rounded bg-black p-3 text-sm text-cyan-100">
                          {artifactPreview.preview}
                        </pre>
                        {artifactPreview.truncated && (
                          <p className="mt-2 text-xs text-amber-300">Preview truncado para mantenerlo ligero.</p>
                        )}
                      </>
                    ) : (
                      <p className="mt-3 text-sm text-gray-300">No hay preview disponible para este artifact. Motivo: {artifactPreview.reason || "binary_or_unsupported"}.</p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-6 py-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-cyan-400 mb-2">Historial Operativo</h1>
          <p className="text-gray-300">Runs unificados con filtros tácticos, linaje y artifacts accionables</p>
        </div>
        <ActionButton icon={<RefreshCw className="w-4 h-4" />} title="Actualizar" description="Refrescar runs" onClick={() => refetch()} />
      </div>

      <Card className="mb-6 bg-gray-800/50 border-gray-700">
        <CardHeader>
          <CardTitle className="text-cyan-400 flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Investigación rápida
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
            <Input
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
              placeholder="Buscar por target, script o acción"
              className="border-gray-700 bg-gray-900 pl-10 text-white"
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="border-gray-700 bg-gray-900 text-white">
              <SelectValue placeholder="Estado" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Todos los estados</SelectItem>
              <SelectItem value="success">success</SelectItem>
              <SelectItem value="failed">failed</SelectItem>
              <SelectItem value="partial">partial</SelectItem>
              <SelectItem value="running">running</SelectItem>
              <SelectItem value="cancelling">cancelling</SelectItem>
              <SelectItem value="cancelled">cancelled</SelectItem>
            </SelectContent>
          </Select>
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="border-gray-700 bg-gray-900 text-white">
              <SelectValue placeholder="Tipo" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Todos los tipos</SelectItem>
              <SelectItem value="script">script</SelectItem>
              <SelectItem value="flow">flow</SelectItem>
              <SelectItem value="lab_session">lab_session</SelectItem>
            </SelectContent>
          </Select>
          <Select value={familyFilter} onValueChange={setFamilyFilter}>
            <SelectTrigger className="border-gray-700 bg-gray-900 text-white">
              <SelectValue placeholder="Familia" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Todas las familias</SelectItem>
              {Array.from(families.keys()).slice(0, 50).map((familyId) => (
                <SelectItem key={familyId} value={familyId}>{familyId}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {isLoading ? (
        <div className="text-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto"></div>
          <p className="text-gray-400 mt-4">Cargando runs...</p>
        </div>
      ) : !filteredRuns.length ? (
        <Card className="bg-gray-800/50 border-gray-700">
          <CardContent className="text-center py-12">
            <Clock className="w-12 h-12 text-gray-500 mx-auto mb-4" />
            <h3 className="text-xl text-gray-400 mb-2">Sin resultados</h3>
            <p className="text-gray-500">Ajusta los filtros o ejecuta nuevas operaciones para seguir investigando.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {filteredRuns.map((run) => {
            const familyRuns = families.get(getRootFamilyId(run)) || [run];
            return (
              <Card key={run.id} className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all cursor-pointer" onClick={() => setSelectedRunId(run.id)}>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between gap-4">
                    <div className="min-w-0">
                      <h3 className="truncate text-lg font-semibold text-white">{run.metadata?.script || run.metadata?.flow_id || run.target || run.requested_action}</h3>
                      <p className="text-sm text-gray-400">{formatTimestamp(run.created_at)}</p>
                      {(run.parent_run_id || run.metadata?.retry_of) && (
                        <p className="text-xs text-yellow-300">retry of {run.parent_run_id || run.metadata?.retry_of}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge>{run.run_type}</Badge>
                      <Badge>{getDisplayStatus(run.status)}</Badge>
                      <ActionButton icon={<Eye className="w-4 h-4" />} title="Ver" description="Ver detalle" onClick={() => setSelectedRunId(run.id)} />
                    </div>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-4 text-sm text-gray-400">
                    <span>Acción: <span className="text-cyan-400">{run.requested_action}</span></span>
                    <span>Steps: {run.step_count ?? 0}</span>
                    <span>Eventos: {run.timeline_count ?? 0}</span>
                    <span>Artifacts: {run.artifact_count ?? 0}</span>
                    <span>Familia: {familyRuns.length} intentos</span>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default History;
