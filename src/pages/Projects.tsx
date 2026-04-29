import { useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/UI/badge";
import { Button } from "@/components/UI/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/UI/card";
import { Input } from "@/components/UI/input";
import { Label } from "@/components/UI/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/UI/select";
import { Textarea } from "@/components/UI/textarea";
import { apiService, useProject, useProjects } from "@/services/api";
import { toast } from "sonner";
import { Boxes, FolderGit2, Globe, Plus, ShieldCheck, Users, Waypoints } from "lucide-react";

const Projects = () => {
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [projectForm, setProjectForm] = useState({
    name: "",
    slug: "",
    description: "",
    project_type: "saas",
  });
  const [memberForm, setMemberForm] = useState({
    username: "",
    role: "member",
  });
  const [environmentForm, setEnvironmentForm] = useState({
    name: "",
    environment_type: "web",
    base_url: "",
    scope: "",
  });

  const { data: projects, refetch: refetchProjects } = useProjects();
  const { data: project, refetch: refetchProject } = useProject(selectedProjectId);

  useEffect(() => {
    if (!selectedProjectId && projects?.length) {
      setSelectedProjectId(projects[0].id);
    }
  }, [projects, selectedProjectId]);

  const runAction = async (key: string, action: () => Promise<void>) => {
    setBusyAction(key);
    try {
      await action();
    } finally {
      setBusyAction(null);
    }
  };

  const createProject = async () => {
    if (!projectForm.name.trim()) {
      toast.error("El nombre del proyecto es obligatorio");
      return;
    }
    await runAction("create-project", async () => {
      const created = await apiService.createProject(projectForm);
      toast.success("Proyecto creado");
      setProjectForm({ name: "", slug: "", description: "", project_type: "saas" });
      await refetchProjects();
      setSelectedProjectId(created.id);
    });
  };

  const addMember = async () => {
    if (!selectedProjectId || !memberForm.username.trim()) {
      toast.error("Necesitas proyecto y username");
      return;
    }
    await runAction("add-member", async () => {
      await apiService.addProjectMember(selectedProjectId, memberForm);
      toast.success("Miembro agregado al proyecto");
      setMemberForm({ username: "", role: "member" });
      await refetchProject();
      await refetchProjects();
    });
  };

  const addEnvironment = async () => {
    if (!selectedProjectId || !environmentForm.name.trim()) {
      toast.error("El entorno necesita nombre");
      return;
    }
    await runAction("add-environment", async () => {
      await apiService.createProjectEnvironment(selectedProjectId, environmentForm);
      toast.success("Entorno creado");
      setEnvironmentForm({ name: "", environment_type: "web", base_url: "", scope: "" });
      await refetchProject();
      await refetchProjects();
    });
  };

  const stats = useMemo(
    () => ({
      members: project?.stats?.member_count ?? project?.members?.length ?? 0,
      environments: project?.stats?.environment_count ?? project?.environments?.length ?? 0,
      workspaces: project?.stats?.workspace_count ?? project?.workspaces?.length ?? 0,
      runs: project?.stats?.recent_run_count ?? project?.recent_runs?.length ?? 0,
    }),
    [project],
  );

  return (
    <div className="container mx-auto max-w-7xl space-y-8 px-6 py-8">
      <section className="rounded-3xl border border-cyan-500/20 bg-gradient-to-br from-slate-950 via-cyan-950/70 to-slate-900 p-8">
        <Badge className="border border-cyan-400/30 bg-cyan-500/15 text-cyan-300">Sotyhub Platform Core</Badge>
        <h1 className="mt-3 text-4xl font-bold text-white">BOFA Projects</h1>
        <p className="mt-2 max-w-3xl text-slate-300">
          El proyecto es ahora la raiz comun para SaaS, bounty, labs y tooling. Desde aqui empezamos a unificar contexto, acceso y entornos.
        </p>
      </section>

      <section className="grid gap-6 xl:grid-cols-[340px,1fr]">
        <Card className="border-slate-800 bg-slate-900/80">
          <CardHeader>
            <CardTitle className="text-cyan-300">Crear proyecto</CardTitle>
            <CardDescription>La unidad compartida para Sotyhub y BOFA.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Nombre</Label>
              <Input value={projectForm.name} onChange={(event) => setProjectForm({ ...projectForm, name: event.target.value })} />
            </div>
            <div className="space-y-2">
              <Label>Slug</Label>
              <Input value={projectForm.slug} onChange={(event) => setProjectForm({ ...projectForm, slug: event.target.value })} placeholder="opcional" />
            </div>
            <div className="space-y-2">
              <Label>Tipo</Label>
              <Select value={projectForm.project_type} onValueChange={(value) => setProjectForm({ ...projectForm, project_type: value })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="saas">saas</SelectItem>
                  <SelectItem value="bug_bounty">bug_bounty</SelectItem>
                  <SelectItem value="labs">labs</SelectItem>
                  <SelectItem value="research">research</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Descripcion</Label>
              <Textarea className="min-h-28" value={projectForm.description} onChange={(event) => setProjectForm({ ...projectForm, description: event.target.value })} />
            </div>
            <Button className="w-full" onClick={createProject} disabled={busyAction === "create-project"}>
              <Plus className="mr-2 h-4 w-4" />
              Crear proyecto
            </Button>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/80">
            <CardHeader>
              <CardTitle className="text-cyan-300">Proyectos activos</CardTitle>
              <CardDescription>Selecciona el contexto comun donde colgaran workspaces, entornos y ejecuciones.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {(projects || []).map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSelectedProjectId(item.id)}
                  className={`rounded-2xl border p-4 text-left ${selectedProjectId === item.id ? "border-cyan-400 bg-cyan-500/10" : "border-slate-800 bg-slate-950/60"}`}
                >
                  <p className="font-medium text-white">{item.name}</p>
                  <p className="text-sm text-slate-400">{item.project_type} · {item.slug}</p>
                </button>
              ))}
            </CardContent>
          </Card>

          {project && (
            <>
              <section className="grid gap-6 lg:grid-cols-4">
                <Card className="border-slate-800 bg-slate-900/80"><CardContent className="p-5"><div className="flex items-center gap-3 text-cyan-300"><Users className="h-5 w-5" />Miembros</div><p className="mt-3 text-3xl font-semibold text-white">{stats.members}</p></CardContent></Card>
                <Card className="border-slate-800 bg-slate-900/80"><CardContent className="p-5"><div className="flex items-center gap-3 text-cyan-300"><Globe className="h-5 w-5" />Entornos</div><p className="mt-3 text-3xl font-semibold text-white">{stats.environments}</p></CardContent></Card>
                <Card className="border-slate-800 bg-slate-900/80"><CardContent className="p-5"><div className="flex items-center gap-3 text-cyan-300"><Waypoints className="h-5 w-5" />Workspaces</div><p className="mt-3 text-3xl font-semibold text-white">{stats.workspaces}</p></CardContent></Card>
                <Card className="border-slate-800 bg-slate-900/80"><CardContent className="p-5"><div className="flex items-center gap-3 text-cyan-300"><FolderGit2 className="h-5 w-5" />Runs</div><p className="mt-3 text-3xl font-semibold text-white">{stats.runs}</p></CardContent></Card>
              </section>

              <section className="grid gap-6 xl:grid-cols-3">
                <Card className="border-slate-800 bg-slate-900/80">
                  <CardHeader>
                    <CardTitle className="text-cyan-300">Miembros</CardTitle>
                    <CardDescription>Primer paso para colaboracion controlada dentro de Sotyhub.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label>Username</Label>
                      <Input value={memberForm.username} onChange={(event) => setMemberForm({ ...memberForm, username: event.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <Label>Rol</Label>
                      <Select value={memberForm.role} onValueChange={(value) => setMemberForm({ ...memberForm, role: value })}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="member">member</SelectItem>
                          <SelectItem value="admin">admin</SelectItem>
                          <SelectItem value="viewer">viewer</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Button className="w-full" variant="outline" onClick={addMember} disabled={busyAction === "add-member"}>
                      <Users className="mr-2 h-4 w-4" />
                      Agregar miembro
                    </Button>
                    <div className="space-y-2">
                      {(project.members || []).map((member) => (
                        <div key={member.id} className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <p className="font-medium text-white">{member.username}</p>
                              <p className="text-xs text-slate-400">{member.email || "sin email publico"}</p>
                            </div>
                            <Badge className="bg-slate-800 text-slate-100">{member.role}</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-slate-800 bg-slate-900/80">
                  <CardHeader>
                    <CardTitle className="text-cyan-300">Entornos</CardTitle>
                    <CardDescription>Base para separar produccion, staging, labs y objetivos de bounty.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label>Nombre</Label>
                      <Input value={environmentForm.name} onChange={(event) => setEnvironmentForm({ ...environmentForm, name: event.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <Label>Tipo</Label>
                      <Select value={environmentForm.environment_type} onValueChange={(value) => setEnvironmentForm({ ...environmentForm, environment_type: value })}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="web">web</SelectItem>
                          <SelectItem value="api">api</SelectItem>
                          <SelectItem value="lab">lab</SelectItem>
                          <SelectItem value="internal">internal</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Base URL</Label>
                      <Input value={environmentForm.base_url} onChange={(event) => setEnvironmentForm({ ...environmentForm, base_url: event.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <Label>Scope</Label>
                      <Textarea className="min-h-24" value={environmentForm.scope} onChange={(event) => setEnvironmentForm({ ...environmentForm, scope: event.target.value })} />
                    </div>
                    <Button className="w-full" variant="outline" onClick={addEnvironment} disabled={busyAction === "add-environment"}>
                      <Globe className="mr-2 h-4 w-4" />
                      Crear entorno
                    </Button>
                    <div className="space-y-2">
                      {(project.environments || []).map((environment) => (
                        <div key={environment.id} className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                          <p className="font-medium text-white">{environment.name}</p>
                          <p className="text-xs text-slate-400">{environment.environment_type} · {environment.base_url || "sin URL base"}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-slate-800 bg-slate-900/80">
                  <CardHeader>
                    <CardTitle className="text-cyan-300">Contexto operativo</CardTitle>
                    <CardDescription>Lo que ya cuelga del proyecto hoy.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                      <div className="flex items-center gap-3 text-cyan-300"><ShieldCheck className="h-5 w-5" />Workspaces bounty</div>
                      <div className="mt-3 space-y-2">
                        {(project.workspaces || []).length === 0 ? (
                          <p className="text-sm text-slate-400">Aun no hay workspaces enlazados.</p>
                        ) : (
                          (project.workspaces || []).map((workspace) => (
                            <div key={workspace.id} className="rounded-lg border border-slate-800 p-3">
                              <p className="font-medium text-white">{workspace.name}</p>
                              <p className="text-xs text-slate-400">{workspace.platform} · {workspace.program_handle}</p>
                            </div>
                          ))
                        )}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                      <div className="flex items-center gap-3 text-cyan-300"><Boxes className="h-5 w-5" />Runs recientes</div>
                      <div className="mt-3 space-y-2">
                        {(project.recent_runs || []).length === 0 ? (
                          <p className="text-sm text-slate-400">Todavia no hay runs asociados directamente al proyecto.</p>
                        ) : (
                          (project.recent_runs || []).map((run) => (
                            <div key={run.id} className="rounded-lg border border-slate-800 p-3">
                              <div className="flex items-center justify-between gap-3">
                                <p className="font-medium text-white">{run.requested_action}</p>
                                <Badge className="bg-slate-800 text-slate-100">{run.status}</Badge>
                              </div>
                              <p className="text-xs text-slate-400">{run.run_type} · {run.target || "sin target"}</p>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </section>
            </>
          )}
        </div>
      </section>
    </div>
  );
};

export default Projects;
