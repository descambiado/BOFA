import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/UI/card";
import { Badge } from "@/components/UI/badge";
import { Button } from "@/components/UI/button";
import { Input } from "@/components/UI/input";
import { Textarea } from "@/components/UI/textarea";
import { Label } from "@/components/UI/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/UI/select";
import { Separator } from "@/components/UI/separator";
import { apiService, useBountySkills, useBountyWorkspace, useBountyWorkspaces, type BountyWorkspace, type NoveltyFinding } from "@/services/api";
import { toast } from "sonner";
import { Activity, BrainCircuit, FolderSearch, GitCompareArrows, Sparkles, Upload, Waypoints } from "lucide-react";

const FINDING_COLORS: Record<string, string> = {
  what_changed: "bg-cyan-500/15 text-cyan-300 border-cyan-400/30",
  what_is_weird: "bg-violet-500/15 text-violet-300 border-violet-400/30",
  worth_manual_time: "bg-emerald-500/15 text-emerald-300 border-emerald-400/30",
  likely_duplicate: "bg-amber-500/15 text-amber-300 border-amber-400/30",
};

const Bounty = () => {
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<string | null>(null);
  const [creatingWorkspace, setCreatingWorkspace] = useState(false);
  const [importingContent, setImportingContent] = useState(false);
  const [analyzingWorkspace, setAnalyzingWorkspace] = useState(false);
  const [runningSkill, setRunningSkill] = useState<string | null>(null);
  const [workspaceForm, setWorkspaceForm] = useState({
    name: "",
    platform: "hackerone",
    program_handle: "",
    notes: "",
  });
  const [importForm, setImportForm] = useState({
    import_type: "scope",
    source_label: "",
    content_format: "txt",
    source_url: "",
    content: "",
  });

  const { data: workspaces, isLoading: workspacesLoading, refetch: refetchWorkspaces } = useBountyWorkspaces();
  const { data: selectedWorkspace, refetch: refetchWorkspace } = useBountyWorkspace(selectedWorkspaceId);
  const { data: skills } = useBountySkills();

  useEffect(() => {
    if (!selectedWorkspaceId && workspaces?.length) {
      setSelectedWorkspaceId(workspaces[0].id);
    }
  }, [workspaces, selectedWorkspaceId]);

  const graphSummary = useMemo(() => {
    const graph = selectedWorkspace?.graph;
    const nodeCount = graph?.nodes?.length ?? 0;
    const edgeCount = graph?.edges?.length ?? 0;
    const assetCount = graph?.assets?.length ?? 0;
    const importCount = graph?.imports?.length ?? 0;
    return { nodeCount, edgeCount, assetCount, importCount };
  }, [selectedWorkspace]);

  const nodeTypeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const node of selectedWorkspace?.graph?.nodes || []) {
      counts.set(node.node_type, (counts.get(node.node_type) || 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [selectedWorkspace]);

  const groupedFindings = useMemo(() => {
    const map = new Map<string, NoveltyFinding[]>();
    for (const finding of selectedWorkspace?.findings || []) {
      const key = finding.category || "unknown";
      map.set(key, [...(map.get(key) || []), finding]);
    }
    return Array.from(map.entries());
  }, [selectedWorkspace]);

  const handleCreateWorkspace = async () => {
    if (!workspaceForm.name.trim() || !workspaceForm.program_handle.trim()) {
      toast.error("Nombre y programa son obligatorios");
      return;
    }
    setCreatingWorkspace(true);
    try {
      const workspace = await apiService.createBountyWorkspace(workspaceForm);
      toast.success("Workspace bounty creado");
      setWorkspaceForm({ name: "", platform: "hackerone", program_handle: "", notes: "" });
      await refetchWorkspaces();
      setSelectedWorkspaceId(workspace.id);
    } catch {
      toast.error("No se pudo crear el workspace bounty");
    } finally {
      setCreatingWorkspace(false);
    }
  };

  const handleImport = async () => {
    if (!selectedWorkspaceId) return;
    if (!importForm.source_label.trim() || !importForm.content.trim()) {
      toast.error("Etiqueta y contenido son obligatorios");
      return;
    }
    setImportingContent(true);
    try {
      await apiService.importBountyWorkspaceContent(selectedWorkspaceId, importForm);
      toast.success("Import ejecutado y trazado como intel_import");
      setImportForm((current) => ({ ...current, content: "" }));
      await refetchWorkspace();
    } catch {
      toast.error("No se pudo importar el contenido");
    } finally {
      setImportingContent(false);
    }
  };

  const handleAnalyze = async () => {
    if (!selectedWorkspaceId) return;
    setAnalyzingWorkspace(true);
    try {
      const result = await apiService.analyzeBountyWorkspace(selectedWorkspaceId);
      toast.success(`Analisis completado: ${result.findings.length} findings priorizados`);
      await refetchWorkspace();
    } catch {
      toast.error("No se pudo analizar el workspace");
    } finally {
      setAnalyzingWorkspace(false);
    }
  };

  const handleRunSkill = async (skillKey: string) => {
    if (!selectedWorkspaceId) return;
    setRunningSkill(skillKey);
    try {
      await apiService.runBountySkill(selectedWorkspaceId, skillKey);
      toast.success(`Skill ejecutada: ${skillKey}`);
      await refetchWorkspace();
    } catch {
      toast.error("No se pudo ejecutar la skill");
    } finally {
      setRunningSkill(null);
    }
  };

  return (
    <div className="container mx-auto max-w-7xl space-y-8 px-6 py-8">
      <section className="rounded-3xl border border-cyan-500/20 bg-gradient-to-br from-slate-950 via-cyan-950/70 to-slate-900 p-8">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="space-y-3">
            <Badge className="bg-cyan-500/15 text-cyan-300 border border-cyan-400/30">Duplicate-Aware Bounty</Badge>
            <div>
              <h1 className="text-4xl font-bold text-white">BOFA Bounty Workspaces</h1>
              <p className="mt-2 max-w-3xl text-slate-300">
                Menos recon plana y menos duplicates. Esta capa intenta responder a tres preguntas útiles:
                qué cambió, qué es raro y qué merece tiempo manual antes de reportar.
              </p>
            </div>
          </div>
          <div className="grid min-w-[280px] grid-cols-2 gap-3">
            <Card className="border-cyan-500/20 bg-slate-950/70">
              <CardContent className="p-4">
                <p className="text-xs uppercase tracking-wide text-slate-400">Workspaces</p>
                <p className="mt-2 text-2xl font-semibold text-white">{workspaces?.length ?? 0}</p>
              </CardContent>
            </Card>
            <Card className="border-cyan-500/20 bg-slate-950/70">
              <CardContent className="p-4">
                <p className="text-xs uppercase tracking-wide text-slate-400">Findings vivos</p>
                <p className="mt-2 text-2xl font-semibold text-white">{selectedWorkspace?.findings?.length ?? 0}</p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[320px,1fr]">
        <Card className="border-slate-800 bg-slate-900/80">
          <CardHeader>
            <CardTitle className="text-cyan-300">Crear workspace</CardTitle>
            <CardDescription>Separa programas, memoria y evidencia por campaña.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Nombre</Label>
              <Input value={workspaceForm.name} onChange={(event) => setWorkspaceForm({ ...workspaceForm, name: event.target.value })} placeholder="Acme H1 main" />
            </div>
            <div className="space-y-2">
              <Label>Plataforma</Label>
              <Select value={workspaceForm.platform} onValueChange={(value) => setWorkspaceForm({ ...workspaceForm, platform: value })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="hackerone">HackerOne</SelectItem>
                  <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                  <SelectItem value="intigriti">Intigriti</SelectItem>
                  <SelectItem value="private">Private</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Programa / handle</Label>
              <Input value={workspaceForm.program_handle} onChange={(event) => setWorkspaceForm({ ...workspaceForm, program_handle: event.target.value })} placeholder="acme-corp" />
            </div>
            <div className="space-y-2">
              <Label>Notas</Label>
              <Textarea value={workspaceForm.notes} onChange={(event) => setWorkspaceForm({ ...workspaceForm, notes: event.target.value })} placeholder="Stack, disclosed notes, strategy..." className="min-h-28" />
            </div>
            <Button className="w-full" onClick={handleCreateWorkspace} disabled={creatingWorkspace}>
              <FolderSearch className="mr-2 h-4 w-4" /> {creatingWorkspace ? "Creando..." : "Crear workspace"}
            </Button>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Workspaces activos</CardTitle>
              <CardDescription>Elige una campaña para ver imports, grafo, findings y skills.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {(workspaces || []).map((workspace: BountyWorkspace) => (
                <button
                  key={workspace.id}
                  type="button"
                  onClick={() => setSelectedWorkspaceId(workspace.id)}
                  className={`rounded-2xl border p-4 text-left transition-all ${selectedWorkspaceId === workspace.id ? "border-cyan-400 bg-cyan-500/10" : "border-slate-800 bg-slate-950/60 hover:border-cyan-500/30"}`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="font-medium text-white">{workspace.name}</p>
                      <p className="text-sm text-slate-400">{workspace.platform} · {workspace.program_handle}</p>
                    </div>
                    <Badge className="bg-slate-800 text-slate-200">{workspace.metadata?.last_snapshot_id ? "con memoria" : "nuevo"}</Badge>
                  </div>
                </button>
              ))}
              {!workspacesLoading && !workspaces?.length && (
                <div className="rounded-2xl border border-dashed border-slate-700 p-6 text-sm text-slate-400">
                  Aun no hay workspaces bounty.
                </div>
              )}
            </CardContent>
          </Card>

          {selectedWorkspace && (
            <>
              <section className="grid gap-6 lg:grid-cols-4">
                <Card className="border-slate-800 bg-slate-900/80">
                  <CardContent className="p-5">
                    <div className="flex items-center gap-3 text-cyan-300"><Waypoints className="h-5 w-5" /> Target Graph</div>
                    <p className="mt-3 text-3xl font-semibold text-white">{graphSummary.nodeCount}</p>
                    <p className="text-sm text-slate-400">{graphSummary.edgeCount} relaciones</p>
                  </CardContent>
                </Card>
                <Card className="border-slate-800 bg-slate-900/80">
                  <CardContent className="p-5">
                    <div className="flex items-center gap-3 text-cyan-300"><Upload className="h-5 w-5" /> Imports</div>
                    <p className="mt-3 text-3xl font-semibold text-white">{graphSummary.importCount}</p>
                    <p className="text-sm text-slate-400">{graphSummary.assetCount} assets</p>
                  </CardContent>
                </Card>
                <Card className="border-slate-800 bg-slate-900/80">
                  <CardContent className="p-5">
                    <div className="flex items-center gap-3 text-cyan-300"><GitCompareArrows className="h-5 w-5" /> What Changed</div>
                    <p className="mt-3 text-3xl font-semibold text-white">{(selectedWorkspace.findings || []).filter((item) => item.category === "what_changed").length}</p>
                    <p className="text-sm text-slate-400">Cambios detectados</p>
                  </CardContent>
                </Card>
                <Card className="border-slate-800 bg-slate-900/80">
                  <CardContent className="p-5">
                    <div className="flex items-center gap-3 text-cyan-300"><Sparkles className="h-5 w-5" /> Worth Manual Time</div>
                    <p className="mt-3 text-3xl font-semibold text-white">{(selectedWorkspace.findings || []).filter((item) => item.category === "worth_manual_time").length}</p>
                    <p className="text-sm text-slate-400">Hipótesis priorizadas</p>
                  </CardContent>
                </Card>
              </section>

              <section className="grid gap-6 xl:grid-cols-[420px,1fr]">
                <Card className="border-slate-800 bg-slate-900/80">
                  <CardHeader>
                    <CardTitle className="text-cyan-300">Import panel</CardTitle>
                    <CardDescription>Scope, disclosed, URL lists, Burp exports, JS endpoints o notas manuales.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label>Tipo</Label>
                        <Select value={importForm.import_type} onValueChange={(value) => setImportForm({ ...importForm, import_type: value })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="scope">scope</SelectItem>
                            <SelectItem value="disclosed_reports">disclosed_reports</SelectItem>
                            <SelectItem value="burp_sitemap">burp_sitemap</SelectItem>
                            <SelectItem value="url_list">url_list</SelectItem>
                            <SelectItem value="js_endpoints">js_endpoints</SelectItem>
                            <SelectItem value="notes">notes</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Formato</Label>
                        <Select value={importForm.content_format} onValueChange={(value) => setImportForm({ ...importForm, content_format: value })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="txt">txt</SelectItem>
                            <SelectItem value="json">json</SelectItem>
                            <SelectItem value="csv">csv</SelectItem>
                            <SelectItem value="md">md</SelectItem>
                            <SelectItem value="html">html</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Etiqueta</Label>
                      <Input value={importForm.source_label} onChange={(event) => setImportForm({ ...importForm, source_label: event.target.value })} placeholder="h1 scope april / disclosed authz batch / burp sitemap beta" />
                    </div>
                    <div className="space-y-2">
                      <Label>URL fuente opcional</Label>
                      <Input value={importForm.source_url} onChange={(event) => setImportForm({ ...importForm, source_url: event.target.value })} placeholder="https://hackerone.com/..." />
                    </div>
                    <div className="space-y-2">
                      <Label>Contenido</Label>
                      <Textarea value={importForm.content} onChange={(event) => setImportForm({ ...importForm, content: event.target.value })} className="min-h-56 font-mono text-xs" placeholder="Pega aquí scope, disclosed reports, URLs, endpoints JS o notas del hunter..." />
                    </div>
                    <div className="flex gap-3">
                      <Button onClick={handleImport} disabled={importingContent} className="flex-1">
                        <Upload className="mr-2 h-4 w-4" /> {importingContent ? "Importando..." : "Importar"}
                      </Button>
                      <Button variant="outline" onClick={handleAnalyze} disabled={analyzingWorkspace}>
                        <BrainCircuit className="mr-2 h-4 w-4" /> {analyzingWorkspace ? "Analizando..." : "Analizar"}
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                <div className="space-y-6">
                  <Card className="border-slate-800 bg-slate-900/80">
                    <CardHeader>
                      <CardTitle className="text-cyan-300">Target graph</CardTitle>
                      <CardDescription>Vista operativa simple: nodos, relaciones y memoria de imports.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-5">
                      <div className="flex flex-wrap gap-2">
                        {nodeTypeCounts.map(([nodeType, count]) => (
                          <Badge key={nodeType} className="bg-slate-800 text-slate-200">{nodeType}: {count}</Badge>
                        ))}
                      </div>
                      <Separator className="bg-slate-800" />
                      <div className="grid gap-3 md:grid-cols-2">
                        {(selectedWorkspace.graph?.nodes || []).slice(0, 16).map((node) => (
                          <div key={node.id} className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                            <div className="flex items-center justify-between gap-2">
                              <Badge className="bg-slate-800 text-slate-100">{node.node_type}</Badge>
                              {(node.metadata?.is_new_since_last_snapshot || node.metadata?.first_snapshot_id === selectedWorkspace.metadata?.last_snapshot_id) && (
                                <Badge className="bg-cyan-500/15 text-cyan-300 border border-cyan-400/30">nuevo</Badge>
                              )}
                            </div>
                            <p className="mt-3 break-all text-sm text-white">{node.value}</p>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="border-slate-800 bg-slate-900/80">
                    <CardHeader>
                      <CardTitle className="text-cyan-300">Novelty queue</CardTitle>
                      <CardDescription>La cola principal para decidir dónde invertir tiempo manual.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-5">
                      {groupedFindings.map(([category, items]) => (
                        <div key={category} className="space-y-3">
                          <div className="flex items-center gap-3">
                            <Badge className={FINDING_COLORS[category] || "bg-slate-800 text-slate-100"}>{category}</Badge>
                            <span className="text-sm text-slate-400">{items.length} findings</span>
                          </div>
                          <div className="grid gap-3">
                            {items.slice(0, 6).map((finding) => (
                              <div key={finding.fingerprint} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                                <div className="flex flex-wrap items-center gap-2">
                                  <p className="font-medium text-white">{finding.title}</p>
                                  <Badge className="bg-slate-800 text-slate-100">novelty {finding.novelty_score}</Badge>
                                  <Badge className="bg-slate-800 text-slate-100">dup risk {finding.duplicate_risk_score}</Badge>
                                </div>
                                <p className="mt-3 text-sm text-slate-300">{finding.rationale}</p>
                                <p className="mt-2 text-xs text-slate-500">evidence: {finding.metadata?.node_type} · {finding.metadata?.node_value}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                      {!selectedWorkspace.findings?.length && (
                        <div className="rounded-xl border border-dashed border-slate-700 p-6 text-sm text-slate-400">
                          Todavía no hay findings. Importa inteligencia y lanza el análisis.
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  <Card className="border-slate-800 bg-slate-900/80">
                    <CardHeader>
                      <CardTitle className="text-cyan-300">Skills bounty</CardTitle>
                      <CardDescription>Copilot táctico: resumen, delta, authz y riesgo de duplicado.</CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-3 md:grid-cols-2">
                      {(skills || []).map((skill) => (
                        <div key={skill.skill_key} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="font-medium text-white">{skill.name}</p>
                              <p className="mt-2 text-sm text-slate-300">{skill.goal}</p>
                            </div>
                            <Badge className="bg-slate-800 text-slate-100">{skill.skill_key}</Badge>
                          </div>
                          <Button className="mt-4 w-full" variant="outline" disabled={runningSkill === skill.skill_key} onClick={() => handleRunSkill(skill.skill_key)}>
                            <Activity className="mr-2 h-4 w-4" /> {runningSkill === skill.skill_key ? "Ejecutando..." : "Run skill"}
                          </Button>
                        </div>
                      ))}
                    </CardContent>
                  </Card>

                  <Card className="border-slate-800 bg-slate-900/80">
                    <CardHeader>
                      <CardTitle className="text-cyan-300">Imports recientes</CardTitle>
                      <CardDescription>Todo queda trazado como `intel_import` y enlazado al workspace.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {(selectedWorkspace.imports || []).slice(0, 8).map((item) => (
                        <div key={item.id} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <p className="font-medium text-white">{item.source_label}</p>
                              <p className="text-sm text-slate-400">{item.import_type} · snapshot {item.snapshot_id || "n/a"}</p>
                            </div>
                            <Badge className="bg-slate-800 text-slate-100">{item.status}</Badge>
                          </div>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </div>
              </section>
            </>
          )}
        </div>
      </section>
    </div>
  );
};

export default Bounty;
