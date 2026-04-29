import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import {
  apiService,
  useBountySkills,
  useBountyWorkspace,
  useBountyWorkspaces,
  useProjects,
  type BountyWorkspace,
  type NoveltyFinding,
  type ReviewQueueItem,
  type SurfaceDelta,
  type WorkspaceSnapshot,
} from "@/services/api";
import { toast } from "sonner";
import { Activity, BrainCircuit, FileJson, FolderSearch, GitCompareArrows, Sparkles, Upload, Waypoints } from "lucide-react";

const Bounty = () => {
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<string | null>(null);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(null);
  const [reviewQueue, setReviewQueue] = useState<ReviewQueueItem[]>([]);
  const [latestDiffs, setLatestDiffs] = useState<SurfaceDelta[]>([]);
  const [latestSnapshot, setLatestSnapshot] = useState<WorkspaceSnapshot | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [tacticalRefreshToken, setTacticalRefreshToken] = useState(0);
  const [workspaceForm, setWorkspaceForm] = useState({ project_id: "", name: "", platform: "hackerone", program_handle: "", notes: "" });
  const [importForm, setImportForm] = useState({ import_type: "scope", source_label: "", content_format: "txt", source_url: "", content: "" });

  const { data: workspaces, refetch: refetchWorkspaces } = useBountyWorkspaces();
  const { data: workspace, refetch: refetchWorkspace } = useBountyWorkspace(selectedWorkspaceId);
  const { data: skills } = useBountySkills();
  const { data: projects } = useProjects();

  useEffect(() => {
    if (!selectedWorkspaceId && workspaces?.length) setSelectedWorkspaceId(workspaces[0].id);
  }, [workspaces, selectedWorkspaceId]);

  useEffect(() => {
    if (!workspace) return;
    const preferredSnapshot = workspace.snapshots?.find((item) => item.snapshot_type === "surface") || workspace.snapshots?.[0] || null;
    setSelectedSnapshotId((current) => current ?? preferredSnapshot?.id ?? null);
  }, [workspace]);

  useEffect(() => {
    const loadTacticalViews = async () => {
      if (!selectedWorkspaceId) return;
      try {
        const [diffPayload, queuePayload] = await Promise.all([
          apiService.getBountyWorkspaceLatestDiffs(selectedWorkspaceId),
          apiService.getBountyWorkspaceReviewQueue(selectedWorkspaceId, selectedSnapshotId),
        ]);
        setLatestSnapshot(diffPayload.snapshot || null);
        setLatestDiffs(diffPayload.deltas || []);
        setReviewQueue(queuePayload.items || []);
      } catch {
        setLatestSnapshot(null);
        setLatestDiffs([]);
        setReviewQueue([]);
      }
    };
    void loadTacticalViews();
  }, [selectedWorkspaceId, selectedSnapshotId, tacticalRefreshToken]);

  const graphSummary = useMemo(() => ({
    nodes: workspace?.graph?.nodes?.length ?? 0,
    edges: workspace?.graph?.edges?.length ?? 0,
    imports: workspace?.imports?.length ?? 0,
    findings: workspace?.findings?.length ?? 0,
  }), [workspace]);

  const groupedFindings = useMemo(() => {
    const groups = new Map<string, NoveltyFinding[]>();
    for (const finding of workspace?.findings || []) {
      const key = finding.category || "unknown";
      groups.set(key, [...(groups.get(key) || []), finding]);
    }
    return Array.from(groups.entries());
  }, [workspace]);

  const selectedSnapshot = useMemo(() => {
    const explicit = workspace?.snapshots?.find((item) => item.id === selectedSnapshotId);
    if (explicit) return explicit;
    return workspace?.snapshots?.find((item) => item.snapshot_type === "surface") || workspace?.snapshots?.[0] || null;
  }, [workspace, selectedSnapshotId]);

  const runAction = async (key: string, action: () => Promise<void>) => {
    setBusyAction(key);
    try {
      await action();
    } finally {
      setBusyAction(null);
    }
  };

  const refreshWorkspaceContext = async () => {
    await refetchWorkspace();
    setTacticalRefreshToken((current) => current + 1);
  };

  const createWorkspace = async () => {
    if (!workspaceForm.name.trim() || !workspaceForm.program_handle.trim()) {
      toast.error("Nombre y programa son obligatorios");
      return;
    }
    await runAction("create-workspace", async () => {
      const created = await apiService.createBountyWorkspace(workspaceForm);
      toast.success("Workspace bounty creado");
      setWorkspaceForm({ project_id: "", name: "", platform: "hackerone", program_handle: "", notes: "" });
      await refetchWorkspaces();
      setSelectedWorkspaceId(created.id);
    });
  };

  const importContent = async () => {
    if (!selectedWorkspaceId) return;
    if (!importForm.source_label.trim() || !importForm.content.trim()) {
      toast.error("Etiqueta y contenido son obligatorios");
      return;
    }
    await runAction("import", async () => {
      const result = await apiService.importBountyWorkspaceContent(selectedWorkspaceId, importForm);
      toast.success(`Import ejecutado en snapshot ${result.snapshot_id}`);
      setImportForm((current) => ({ ...current, content: "" }));
      await refreshWorkspaceContext();
      setSelectedSnapshotId(result.snapshot_id);
    });
  };

  const analyzeWorkspace = async () => {
    if (!selectedWorkspaceId) return;
    await runAction("analyze", async () => {
      const result = await apiService.analyzeBountyWorkspace(selectedWorkspaceId);
      toast.success(`Analisis completado: ${result.findings.length} findings y ${result.review_queue?.length || 0} items`);
      await refreshWorkspaceContext();
    });
  };

  const runSkill = async (skillKey: string) => {
    if (!selectedWorkspaceId) return;
    await runAction(`skill:${skillKey}`, async () => {
      await apiService.runBountySkill(selectedWorkspaceId, skillKey);
      toast.success(`Skill ejecutada: ${skillKey}`);
      await refreshWorkspaceContext();
    });
  };

  const exportQueue = async () => {
    if (!selectedWorkspaceId) return;
    await runAction("export-queue", async () => {
      const result = await apiService.exportBountyWorkspaceReviewQueue(selectedWorkspaceId, selectedSnapshot?.id || null);
      toast.success(`Review queue exportada con ${result.item_count} items`);
      await refreshWorkspaceContext();
    });
  };

  return (
    <div className="container mx-auto max-w-7xl space-y-8 px-6 py-8">
      <section className="rounded-3xl border border-cyan-500/20 bg-gradient-to-br from-slate-950 via-cyan-950/70 to-slate-900 p-8">
        <Badge className="border border-cyan-400/30 bg-cyan-500/15 text-cyan-300">Duplicate-Aware Bounty</Badge>
        <h1 className="mt-3 text-4xl font-bold text-white">BOFA Bounty Workspaces</h1>
        <p className="mt-2 max-w-3xl text-slate-300">BOFA intenta responder que cambio, que es raro y que tiene menos riesgo de ser duplicate.</p>
      </section>

      <section className="grid gap-6 xl:grid-cols-[320px,1fr]">
        <Card className="border-slate-800 bg-slate-900/80">
          <CardHeader>
            <CardTitle className="text-cyan-300">Crear workspace</CardTitle>
            <CardDescription>Una memoria operativa por programa.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Proyecto</Label>
              <Select value={workspaceForm.project_id || "none"} onValueChange={(value) => setWorkspaceForm({ ...workspaceForm, project_id: value === "none" ? "" : value })}>
                <SelectTrigger><SelectValue placeholder="Sin proyecto" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">Sin proyecto</SelectItem>
                  {(projects || []).map((project) => (
                    <SelectItem key={project.id} value={project.id}>{project.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2"><Label>Nombre</Label><Input value={workspaceForm.name} onChange={(event) => setWorkspaceForm({ ...workspaceForm, name: event.target.value })} /></div>
            <div className="space-y-2"><Label>Plataforma</Label><Input value={workspaceForm.platform} onChange={(event) => setWorkspaceForm({ ...workspaceForm, platform: event.target.value })} /></div>
            <div className="space-y-2"><Label>Programa</Label><Input value={workspaceForm.program_handle} onChange={(event) => setWorkspaceForm({ ...workspaceForm, program_handle: event.target.value })} /></div>
            <div className="space-y-2"><Label>Notas</Label><Textarea className="min-h-24" value={workspaceForm.notes} onChange={(event) => setWorkspaceForm({ ...workspaceForm, notes: event.target.value })} /></div>
            <Button className="w-full" onClick={createWorkspace} disabled={busyAction === "create-workspace"}><FolderSearch className="mr-2 h-4 w-4" />Crear workspace</Button>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Workspaces activos</CardTitle>
              <CardDescription>Selecciona una campana para ver snapshots, deltas y review queue.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {(workspaces || []).map((item: BountyWorkspace) => (
                <button key={item.id} type="button" onClick={() => { setSelectedWorkspaceId(item.id); setSelectedSnapshotId(null); }} className={`rounded-2xl border p-4 text-left ${selectedWorkspaceId === item.id ? "border-cyan-400 bg-cyan-500/10" : "border-slate-800 bg-slate-950/60"}`}>
                  <p className="font-medium text-white">{item.name}</p>
                  <p className="text-sm text-slate-400">{item.platform} · {item.program_handle}</p>
                </button>
              ))}
            </CardContent>
          </Card>

          {workspace && (
            <>
              <section className="grid gap-6 lg:grid-cols-4">
                <Card className="border-slate-800 bg-slate-900/80"><CardContent className="p-5"><div className="flex items-center gap-3 text-cyan-300"><Waypoints className="h-5 w-5" />Graph</div><p className="mt-3 text-3xl font-semibold text-white">{graphSummary.nodes}</p><p className="text-sm text-slate-400">{graphSummary.edges} relaciones</p></CardContent></Card>
                <Card className="border-slate-800 bg-slate-900/80"><CardContent className="p-5"><div className="flex items-center gap-3 text-cyan-300"><Upload className="h-5 w-5" />Imports</div><p className="mt-3 text-3xl font-semibold text-white">{graphSummary.imports}</p><p className="text-sm text-slate-400">{workspace.snapshots?.length || 0} snapshots</p></CardContent></Card>
                <Card className="border-slate-800 bg-slate-900/80"><CardContent className="p-5"><div className="flex items-center gap-3 text-cyan-300"><GitCompareArrows className="h-5 w-5" />What Changed</div><p className="mt-3 text-3xl font-semibold text-white">{latestDiffs.length}</p><p className="text-sm text-slate-400">{latestSnapshot?.label || "snapshot actual"}</p></CardContent></Card>
                <Card className="border-slate-800 bg-slate-900/80"><CardContent className="p-5"><div className="flex items-center gap-3 text-cyan-300"><Sparkles className="h-5 w-5" />Review Queue</div><p className="mt-3 text-3xl font-semibold text-white">{reviewQueue.length}</p><p className="text-sm text-slate-400">{graphSummary.findings} findings vivos</p></CardContent></Card>
              </section>

              <section className="grid gap-6 xl:grid-cols-[400px,1fr]">
                <Card className="border-slate-800 bg-slate-900/80">
                  <CardHeader>
                    <CardTitle className="text-cyan-300">Import panel</CardTitle>
                    <CardDescription>Scope, disclosed, URLs, JS endpoints o notas manuales.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2"><Label>Tipo</Label><Select value={importForm.import_type} onValueChange={(value) => setImportForm({ ...importForm, import_type: value })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="scope">scope</SelectItem><SelectItem value="disclosed_reports">disclosed_reports</SelectItem><SelectItem value="burp_sitemap">burp_sitemap</SelectItem><SelectItem value="url_list">url_list</SelectItem><SelectItem value="js_endpoints">js_endpoints</SelectItem><SelectItem value="notes">notes</SelectItem></SelectContent></Select></div>
                      <div className="space-y-2"><Label>Formato</Label><Select value={importForm.content_format} onValueChange={(value) => setImportForm({ ...importForm, content_format: value })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="txt">txt</SelectItem><SelectItem value="json">json</SelectItem><SelectItem value="csv">csv</SelectItem><SelectItem value="md">md</SelectItem><SelectItem value="html">html</SelectItem></SelectContent></Select></div>
                    </div>
                    <div className="space-y-2"><Label>Etiqueta</Label><Input value={importForm.source_label} onChange={(event) => setImportForm({ ...importForm, source_label: event.target.value })} /></div>
                    <div className="space-y-2"><Label>URL fuente</Label><Input value={importForm.source_url} onChange={(event) => setImportForm({ ...importForm, source_url: event.target.value })} /></div>
                    <div className="space-y-2"><Label>Contenido</Label><Textarea className="min-h-56 font-mono text-xs" value={importForm.content} onChange={(event) => setImportForm({ ...importForm, content: event.target.value })} /></div>
                    <div className="flex gap-3">
                      <Button className="flex-1" onClick={importContent} disabled={busyAction === "import"}><Upload className="mr-2 h-4 w-4" />Importar</Button>
                      <Button variant="outline" onClick={analyzeWorkspace} disabled={busyAction === "analyze"}><BrainCircuit className="mr-2 h-4 w-4" />Analizar</Button>
                    </div>
                  </CardContent>
                </Card>

                <div className="space-y-6">
                  <Card className="border-slate-800 bg-slate-900/80">
                    <CardHeader>
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                        <div>
                          <CardTitle className="text-cyan-300">Snapshots y deltas</CardTitle>
                          <CardDescription>La foto operativa para entender por que algo merece minutos humanos.</CardDescription>
                        </div>
                        <div className="flex gap-3">
                          <Select value={selectedSnapshot?.id || ""} onValueChange={(value) => setSelectedSnapshotId(value)}><SelectTrigger className="min-w-[240px]"><SelectValue /></SelectTrigger><SelectContent>{(workspace.snapshots || []).map((item) => <SelectItem key={item.id} value={item.id}>{item.label || item.source || item.id}</SelectItem>)}</SelectContent></Select>
                          <Button variant="outline" onClick={exportQueue} disabled={busyAction === "export-queue"}><FileJson className="mr-2 h-4 w-4" />Exportar queue</Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex flex-wrap gap-2">{(workspace.snapshots || []).slice(0, 8).map((item) => <Badge key={item.id} className={item.id === selectedSnapshot?.id ? "border border-cyan-400/30 bg-cyan-500/15 text-cyan-300" : "bg-slate-800 text-slate-200"}>{item.snapshot_type} · {item.label || item.source || item.id}</Badge>)}</div>
                      <Separator className="bg-slate-800" />
                      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{(latestDiffs || []).slice(0, 12).map((delta) => <div key={delta.id} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"><Badge className="bg-slate-800 text-slate-200">{delta.change_type}</Badge><p className="mt-3 break-all text-sm text-white">{delta.entity_label || delta.entity_key}</p><p className="mt-2 text-xs text-slate-500">{delta.entity_type}</p></div>)}</div>
                    </CardContent>
                  </Card>

                  <Card className="border-slate-800 bg-slate-900/80">
                    <CardHeader>
                      <CardTitle className="text-cyan-300">Review Queue</CardTitle>
                      <CardDescription>Hypothesis, why now, evidence, scores y siguiente paso manual.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {reviewQueue.slice(0, 12).map((item) => (
                        <div key={item.cluster_key} className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                          <div className="grid gap-4 lg:grid-cols-[2fr,1fr,1fr,2fr]">
                            <div><p className="text-xs uppercase tracking-wide text-slate-500">Hypothesis</p><p className="mt-2 font-medium text-white">{item.hypothesis}</p><p className="mt-2 text-sm text-slate-300">{item.why_now}</p></div>
                            <div><p className="text-xs uppercase tracking-wide text-slate-500">Evidence</p><p className="mt-2 text-sm text-slate-300">{item.evidence.length} links</p><p className="mt-2 text-sm text-cyan-300">novelty {item.novelty_score}</p><p className="text-sm text-amber-300">dup risk {item.duplicate_risk_score}</p></div>
                            <div><p className="text-xs uppercase tracking-wide text-slate-500">Signal</p><div className="mt-2 flex flex-wrap gap-2">{item.report_candidate && <Badge className="border border-emerald-400/30 bg-emerald-500/15 text-emerald-300">report candidate</Badge>}{item.root_cause && <Badge className="bg-slate-800 text-slate-200">{item.root_cause}</Badge>}</div></div>
                            <div><p className="text-xs uppercase tracking-wide text-slate-500">Next Manual Step</p><p className="mt-2 text-sm text-slate-300">{item.next_manual_step}</p></div>
                          </div>
                        </div>
                      ))}
                      {!reviewQueue.length && <div className="rounded-xl border border-dashed border-slate-700 p-6 text-sm text-slate-400">La review queue aparecera cuando haya findings agrupados con evidencia y siguiente paso manual.</div>}
                    </CardContent>
                  </Card>

                  <Card className="border-slate-800 bg-slate-900/80">
                    <CardHeader><CardTitle className="text-cyan-300">Skills bounty</CardTitle><CardDescription>Copilot tactico sobre el mismo contexto del workspace.</CardDescription></CardHeader>
                    <CardContent className="grid gap-3 md:grid-cols-2">{(skills || []).map((skill) => <div key={skill.skill_key} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"><p className="font-medium text-white">{skill.name}</p><p className="mt-2 text-sm text-slate-300">{skill.goal}</p><Button className="mt-4 w-full" variant="outline" disabled={busyAction === `skill:${skill.skill_key}`} onClick={() => runSkill(skill.skill_key)}><Activity className="mr-2 h-4 w-4" />Run skill</Button></div>)}</CardContent>
                  </Card>

                  <Card className="border-slate-800 bg-slate-900/80">
                    <CardHeader><CardTitle className="text-cyan-300">Novelty queue</CardTitle><CardDescription>Findings vivos agrupados por categoria.</CardDescription></CardHeader>
                    <CardContent className="space-y-5">
                      {groupedFindings.map(([category, items]) => (
                        <div key={category} className="space-y-3">
                          <div className="flex items-center gap-3"><Badge className="bg-slate-800 text-slate-200">{category}</Badge><span className="text-sm text-slate-400">{items?.length || 0} findings</span></div>
                          <div className="grid gap-3">{(items || []).slice(0, 4).map((finding) => <div key={finding.fingerprint} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"><p className="font-medium text-white">{finding.title}</p><p className="mt-2 text-sm text-slate-300">{finding.rationale}</p><p className="mt-2 text-xs text-cyan-300">{String(finding.metadata?.next_manual_step || "")}</p></div>)}</div>
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
