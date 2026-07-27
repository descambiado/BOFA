import { type ComponentType, useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { ScriptExecutor } from "@/components/ScriptExecutor";
import {
  AlertTriangle,
  BookOpen,
  Brain,
  Bug,
  Calendar,
  Cloud,
  Crosshair,
  FileCode2,
  FileText,
  Fingerprint,
  FlaskConical,
  Globe,
  KeyRound,
  Lock,
  Package,
  Play,
  Radar,
  Search,
  Shield,
  ShieldAlert,
  Star,
  Tag,
  Terminal,
  User,
  Users,
  Zap,
} from "lucide-react";
import { useModules, useScripts, Module } from "@/services/api";
import { ScriptConfig } from "@/types/script";

const moduleIcons: Record<string, ComponentType<{ className?: string }>> = {
  ai: Brain,
  blue: Shield,
  cloud: Cloud,
  crypto: KeyRound,
  dockerlabs: FlaskConical,
  examples: FileCode2,
  exploit: Bug,
  forensics: Fingerprint,
  malware: Bug,
  osint: Search,
  purple: Users,
  recon: Radar,
  red: Crosshair,
  reporting: FileText,
  social: Users,
  study: BookOpen,
  supply_chain: Package,
  vulnerability: ShieldAlert,
  web: Globe,
  zero_trust: Lock,
};

const isRecentScript = (script: ScriptConfig) =>
  script.is_recent || script.last_updated === "2025-01-20" || script.last_updated === "2026-01-20";

const getErrorMessage = (error: unknown, fallback: string) =>
  error instanceof Error ? error.message : fallback;

const Scripts = () => {
  const [selectedModule, setSelectedModule] = useState<string>("");
  const [selectedScript, setSelectedScript] = useState<ScriptConfig | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterRisk, setFilterRisk] = useState<string>("all");
  const [filterRecent, setFilterRecent] = useState<boolean>(false);

  const {
    data: modules,
    isLoading: modulesLoading,
    error: modulesError,
  } = useModules();
  const {
    data: scripts,
    isLoading: scriptsLoading,
    error: scriptsError,
  } = useScripts(selectedModule);

  const selectedModuleMeta = useMemo(
    () => modules?.find((module) => module.id === selectedModule) || null,
    [modules, selectedModule],
  );

  const filteredScripts = useMemo(() => {
    return (
      scripts?.filter((script) => {
        const matchesSearch =
          script.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          script.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
          script.tags?.some((tag) => tag.toLowerCase().includes(searchTerm.toLowerCase()));

        const matchesRisk = filterRisk === "all" || script.risk_level === filterRisk.toUpperCase();
        const matchesRecent = !filterRecent || isRecentScript(script);

        return matchesSearch && matchesRisk && matchesRecent;
      }) || []
    );
  }, [scripts, searchTerm, filterRisk, filterRecent]);

  const recentCount = scripts?.filter((script) => isRecentScript(script)).length || 0;

  if (selectedScript) {
    return (
      <ScriptExecutor
        module={selectedModule}
        script={selectedScript}
        onBack={() => setSelectedScript(null)}
        onExecutionComplete={() => {
          // Keep the operator inside the current module after execution.
        }}
      />
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-slate-900 to-black p-6 text-white">
      <div className="container mx-auto max-w-7xl space-y-8">
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-4xl font-bold text-cyan-300">Runtime Scripts</h1>
            <Badge className="bg-cyan-500/15 text-cyan-200 border border-cyan-400/20">
              <Zap className="mr-1 h-3 w-3" />
              {selectedModule ? `${filteredScripts.length} visibles` : `${modules?.length || 0} modulos`}
            </Badge>
            {selectedModuleMeta?.recent_script_count ? (
              <Badge className="bg-emerald-500/15 text-emerald-200 border border-emerald-400/20">
                {selectedModuleMeta.recent_script_count} recientes
              </Badge>
            ) : null}
          </div>
          <p className="max-w-3xl text-lg text-slate-300">
            Esta vista ya no depende de un catalogo estatico del cliente. BOFA carga modulos y scripts desde el runtime
            para que lo que ejecutas y lo que ves pertenezcan a la misma fuente.
          </p>
        </div>

        {modulesError ? (
          <div className="flex items-start gap-3 rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-amber-100">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
            <div>
              <p className="font-medium">No se pudo cargar el catalogo del runtime</p>
              <p className="text-sm text-amber-100/80">
                {getErrorMessage(modulesError, "La API de BOFA no responde para /modules.")}
              </p>
            </div>
          </div>
        ) : null}

        {!selectedModule ? (
          <section className="space-y-6">
            <div>
              <h2 className="text-2xl font-bold text-cyan-300">Selecciona un modulo</h2>
              <p className="mt-1 text-sm text-slate-400">
                Cada modulo refleja una carpeta real del runtime y su metadata actual.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {modulesLoading
                ? Array.from({ length: 8 }).map((_, index) => (
                    <Card key={index} className="border-gray-800 bg-gray-900/60 animate-pulse">
                      <CardContent className="p-6">
                        <div className="mb-4 h-16 rounded bg-gray-800" />
                        <div className="mb-2 h-4 rounded bg-gray-800" />
                        <div className="h-3 rounded bg-gray-800" />
                      </CardContent>
                    </Card>
                  ))
                : modules?.map((module: Module) => {
                    const Icon = moduleIcons[module.id] || Terminal;
                    return (
                      <Card
                        key={module.id}
                        className="cursor-pointer border-gray-800 bg-gray-900/60 transition-all hover:scale-[1.02] hover:border-cyan-400/60"
                        onClick={() => setSelectedModule(module.id)}
                      >
                        <CardHeader>
                          <div className="flex items-center justify-between gap-3">
                            <Icon className="h-8 w-8 text-cyan-300" />
                            <div className="flex gap-2">
                              <Badge className="bg-cyan-600 text-white">{module.script_count} scripts</Badge>
                              {module.recent_script_count ? (
                                <Badge className="bg-emerald-600 text-white">{module.recent_script_count} recientes</Badge>
                              ) : null}
                            </div>
                          </div>
                          <CardTitle className="text-cyan-300">{module.name}</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <CardDescription className="text-slate-300">{module.description}</CardDescription>
                        </CardContent>
                      </Card>
                    );
                  })}
            </div>

            {!modulesLoading && !modules?.length && !modulesError ? (
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-8 text-center text-slate-300">
                El runtime no devolvio modulos cargados.
              </div>
            ) : null}
          </section>
        ) : (
          <section className="space-y-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
              <div className="flex items-start gap-4">
                <Button
                  variant="outline"
                  onClick={() => setSelectedModule("")}
                  className="border-cyan-400 text-cyan-300 hover:bg-cyan-400 hover:text-black"
                >
                  Volver a modulos
                </Button>
                <div>
                  <h2 className="text-3xl font-bold text-cyan-300">
                    {selectedModuleMeta?.name || selectedModule}
                  </h2>
                  <p className="mt-1 max-w-2xl text-slate-300">
                    {selectedModuleMeta?.description || "Scripts cargados desde el runtime de BOFA."}
                  </p>
                </div>
              </div>

              <div className="text-sm text-slate-400">
                {filteredScripts.length} scripts visibles
              </div>
            </div>

            {scriptsError ? (
              <div className="flex items-start gap-3 rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-amber-100">
                <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
                <div>
                  <p className="font-medium">No se pudo cargar el modulo seleccionado</p>
                  <p className="text-sm text-amber-100/80">
                    {getErrorMessage(scriptsError, "La API de BOFA no responde para /modules/{module}/scripts.")}
                  </p>
                </div>
              </div>
            ) : null}

            <Card className="border-gray-800 bg-gray-900/60">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-cyan-300">
                  <Search className="h-5 w-5" />
                  Filtros
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
                  <div>
                    <label className="mb-2 block text-sm text-slate-400">Buscar</label>
                    <Input
                      placeholder="Nombre, descripcion o tag"
                      value={searchTerm}
                      onChange={(event) => setSearchTerm(event.target.value)}
                      className="border-gray-700 bg-gray-800 text-white"
                    />
                  </div>
                  <div>
                    <label className="mb-2 block text-sm text-slate-400">Riesgo</label>
                    <Select value={filterRisk} onValueChange={setFilterRisk}>
                      <SelectTrigger className="border-gray-700 bg-gray-800 text-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">Todos</SelectItem>
                        <SelectItem value="low">Bajo</SelectItem>
                        <SelectItem value="medium">Medio</SelectItem>
                        <SelectItem value="high">Alto</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="mb-2 block text-sm text-slate-400">Recientes</label>
                    <Button
                      variant={filterRecent ? "default" : "outline"}
                      onClick={() => setFilterRecent(!filterRecent)}
                      className={
                        filterRecent
                          ? "bg-cyan-600 hover:bg-cyan-700"
                          : "border-gray-700 text-slate-300 hover:bg-gray-800"
                      }
                    >
                      <Zap className="mr-2 h-4 w-4" />
                      {filterRecent ? "Solo recientes" : "Mostrar recientes"}
                    </Button>
                  </div>
                  <div className="flex items-end">
                    <Button
                      variant="outline"
                      onClick={() => {
                        setSearchTerm("");
                        setFilterRisk("all");
                        setFilterRecent(false);
                      }}
                      className="border-gray-700 text-slate-300 hover:bg-gray-800"
                    >
                      Limpiar filtros
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2 xl:grid-cols-3">
              {scriptsLoading
                ? Array.from({ length: 6 }).map((_, index) => (
                    <Card key={index} className="border-gray-800 bg-gray-900/60 animate-pulse">
                      <CardContent className="p-6">
                        <div className="mb-4 h-6 rounded bg-gray-800" />
                        <div className="mb-2 h-4 rounded bg-gray-800" />
                        <div className="mb-4 h-4 rounded bg-gray-800" />
                        <div className="h-10 rounded bg-gray-800" />
                      </CardContent>
                    </Card>
                  ))
                : filteredScripts.map((script) => (
                    <Card
                      key={script.name}
                      className="border-gray-800 bg-gray-900/60 transition-all hover:scale-[1.02] hover:border-cyan-400/60"
                    >
                      <CardHeader>
                        <div className="mb-2 flex items-start justify-between gap-3">
                          <CardTitle className="text-lg text-cyan-300">
                            {script.display_name || script.name}
                          </CardTitle>
                          {isRecentScript(script) ? (
                            <Badge className="bg-emerald-600 text-white">Reciente</Badge>
                          ) : null}
                        </div>
                        <CardDescription className="line-clamp-3 text-slate-300">
                          {script.description}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="grid grid-cols-2 gap-4 text-xs">
                          <div className="flex items-center text-slate-400">
                            <User className="mr-1 h-3 w-3" />
                            {script.author}
                          </div>
                          <div className="flex items-center text-slate-400">
                            <Calendar className="mr-1 h-3 w-3" />
                            {script.version}
                          </div>
                          {script.educational_value ? (
                            <div className="flex items-center text-slate-400">
                              <Star className="mr-1 h-3 w-3" />
                              {Array.from({ length: script.educational_value }, (_, index) => (
                                <span key={index} className="text-yellow-400">
                                  *
                                </span>
                              ))}
                            </div>
                          ) : null}
                          {script.risk_level ? (
                            <div className="flex items-center">
                              <span
                                className={`rounded px-2 py-1 text-xs font-bold ${
                                  script.risk_level === "HIGH"
                                    ? "bg-red-600 text-white"
                                    : script.risk_level === "MEDIUM"
                                      ? "bg-yellow-500 text-black"
                                      : "bg-green-600 text-white"
                                }`}
                              >
                                {script.risk_level}
                              </span>
                            </div>
                          ) : null}
                        </div>

                        {script.tags?.length ? (
                          <div className="flex flex-wrap gap-1">
                            {script.tags.slice(0, 3).map((tag) => (
                              <span
                                key={tag}
                                className="flex items-center rounded bg-gray-800 px-2 py-1 text-xs text-cyan-300"
                              >
                                <Tag className="mr-1 h-2 w-2" />
                                {tag}
                              </span>
                            ))}
                            {script.tags.length > 3 ? (
                              <span className="rounded bg-gray-800 px-2 py-1 text-xs text-slate-400">
                                +{script.tags.length - 3} mas
                              </span>
                            ) : null}
                          </div>
                        ) : null}

                        <Button
                          onClick={() => setSelectedScript(script)}
                          className="w-full bg-green-600 text-white hover:bg-green-700"
                        >
                          <Play className="mr-2 h-4 w-4" />
                          Ejecutar script
                        </Button>
                      </CardContent>
                    </Card>
                  ))}
            </div>

            {!scriptsLoading && !filteredScripts.length ? (
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 py-12 text-center">
                <Search className="mx-auto mb-4 h-16 w-16 text-slate-500" />
                <h3 className="mb-2 text-xl font-semibold text-slate-300">No hay scripts que coincidan</h3>
                <p className="text-slate-500">Prueba a relajar los filtros o vuelve al listado de modulos.</p>
              </div>
            ) : null}
          </section>
        )}
      </div>
    </div>
  );
};

export default Scripts;
