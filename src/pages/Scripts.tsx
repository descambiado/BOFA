
import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { ScriptExecutor } from "@/components/ScriptExecutor";
import { ActionButton } from "@/components/UI/ActionButton";
import { 
  Terminal, 
  Shield, 
  Users, 
  Search, 
  Bug, 
  BookOpen,
  Filter,
  Play,
  Star,
  Calendar,
  User,
  Tag,
  Zap
} from "lucide-react";
import { useModules, useScripts } from "@/services/api";
import { ScriptConfig } from "@/types/script";

const Scripts = () => {
  const [selectedModule, setSelectedModule] = useState<string>("");
  const [selectedScript, setSelectedScript] = useState<ScriptConfig | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterRisk, setFilterRisk] = useState<string>("all");
  const [filterNew, setFilterNew] = useState<boolean>(false);

  const { data: modules, isLoading: modulesLoading } = useModules();
  const { data: scripts, isLoading: scriptsLoading } = useScripts(selectedModule);

  const moduleIcons: Record<string, any> = {
    red: Terminal,
    blue: Shield,
    purple: Users,
    osint: Search,
    malware: Bug,
    social: Users,
    study: BookOpen
  };

  const filteredScripts = scripts?.filter(script => {
    const matchesSearch = script.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         script.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         script.tags?.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesRisk = filterRisk === "all" || script.risk_level === filterRisk.toUpperCase();
    const matchesNew = !filterNew || script.last_updated === "2025-01-20";
    
    return matchesSearch && matchesRisk && matchesNew;
  }) || [];

  if (selectedScript) {
    return (
      <ScriptExecutor
        module={selectedModule}
        script={selectedScript}
        onBack={() => setSelectedScript(null)}
        onExecutionComplete={() => {
          // Handle execution completion if needed
        }}
      />
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto max-w-7xl">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center space-x-4 mb-4">
            <h1 className="text-4xl font-bold text-cyan-400">Scripts & Herramientas</h1>
            <Badge className="bg-gradient-to-r from-cyan-500 to-purple-500 text-white animate-pulse">
              <Zap className="w-3 h-3 mr-1" />
              {scripts?.filter(s => s.last_updated === "2025-01-20").length || 0} NUEVOS 2025
            </Badge>
          </div>
          <p className="text-gray-300 text-lg">
            Explora nuestro arsenal completo de herramientas de ciberseguridad con tecnologías 2025
          </p>
        </div>

        {/* Module Selection */}
        {!selectedModule && (
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-cyan-400 mb-6">Selecciona un Módulo</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              {modulesLoading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <Card key={i} className="bg-gray-800/50 border-gray-700 animate-pulse">
                    <CardContent className="p-6">
                      <div className="h-16 bg-gray-700 rounded mb-4"></div>
                      <div className="h-4 bg-gray-700 rounded mb-2"></div>
                      <div className="h-3 bg-gray-700 rounded"></div>
                    </CardContent>
                  </Card>
                ))
              ) : (
                modules?.map((module) => {
                  const Icon = moduleIcons[module.id] || Terminal;
                  return (
                    <Card 
                      key={module.id} 
                      className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all cursor-pointer transform hover:scale-105"
                      onClick={() => setSelectedModule(module.id)}
                    >
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <Icon className="w-8 h-8 text-cyan-400" />
                          <Badge className="bg-cyan-600 text-white">
                            {module.script_count} scripts
                          </Badge>
                        </div>
                        <CardTitle className="text-cyan-400">{module.name}</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <CardDescription className="text-gray-300">
                          {module.description}
                        </CardDescription>
                      </CardContent>
                    </Card>
                  );
                })
              )}
            </div>
          </div>
        )}

        {/* Script List */}
        {selectedModule && (
          <div className="space-y-6">
            {/* Module Header */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <Button 
                  variant="outline" 
                  onClick={() => setSelectedModule("")}
                  className="border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black"
                >
                  ← Volver a Módulos
                </Button>
                <div>
                  <h2 className="text-3xl font-bold text-cyan-400">
                    {modules?.find(m => m.id === selectedModule)?.name}
                  </h2>
                  <p className="text-gray-300">
                    {filteredScripts.length} scripts disponibles
                  </p>
                </div>
              </div>
            </div>

            {/* Filters */}
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-cyan-400 flex items-center">
                  <Filter className="w-5 h-5 mr-2" />
                  Filtros y Búsqueda
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div>
                    <label className="text-sm text-gray-400 mb-2 block">Buscar</label>
                    <Input
                      placeholder="Buscar scripts..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="bg-gray-700 border-gray-600 text-white"
                    />
                  </div>
                  <div>
                    <label className="text-sm text-gray-400 mb-2 block">Nivel de Riesgo</label>
                    <Select value={filterRisk} onValueChange={setFilterRisk}>
                      <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
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
                    <label className="text-sm text-gray-400 mb-2 block">Scripts Nuevos 2025</label>
                    <Button
                      variant={filterNew ? "default" : "outline"}
                      onClick={() => setFilterNew(!filterNew)}
                      className={filterNew ? "bg-cyan-600 hover:bg-cyan-700" : "border-gray-600 text-gray-300"}
                    >
                      <Zap className="w-4 h-4 mr-2" />
                      {filterNew ? "Mostrando Nuevos" : "Mostrar Nuevos"}
                    </Button>
                  </div>
                  <div className="flex items-end">
                    <Button
                      variant="outline"
                      onClick={() => {
                        setSearchTerm("");
                        setFilterRisk("all");
                        setFilterNew(false);
                      }}
                      className="border-gray-600 text-gray-300 hover:bg-gray-700"
                    >
                      Limpiar Filtros
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Scripts Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
              {scriptsLoading ? (
                Array.from({ length: 6 }).map((_, i) => (
                  <Card key={i} className="bg-gray-800/50 border-gray-700 animate-pulse">
                    <CardContent className="p-6">
                      <div className="h-6 bg-gray-700 rounded mb-4"></div>
                      <div className="h-4 bg-gray-700 rounded mb-2"></div>
                      <div className="h-4 bg-gray-700 rounded mb-4"></div>
                      <div className="h-10 bg-gray-700 rounded"></div>
                    </CardContent>
                  </Card>
                ))
              ) : filteredScripts.length === 0 ? (
                <div className="col-span-full text-center py-12">
                  <Search className="w-16 h-16 text-gray-500 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-400 mb-2">No se encontraron scripts</h3>
                  <p className="text-gray-500">Intenta ajustar los filtros de búsqueda</p>
                </div>
              ) : (
                filteredScripts.map((script) => (
                  <Card 
                    key={script.name} 
                    className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all transform hover:scale-105"
                  >
                    <CardHeader>
                      <div className="flex items-start justify-between mb-2">
                        <CardTitle className="text-cyan-400 text-lg">
                          {script.display_name || script.name}
                        </CardTitle>
                        {script.last_updated === "2025-01-20" && (
                          <Badge className="bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-xs animate-pulse">
                            ✨ NUEVO
                          </Badge>
                        )}
                      </div>
                      <CardDescription className="text-gray-300 line-clamp-3">
                        {script.description}
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {/* Script Metadata */}
                      <div className="grid grid-cols-2 gap-4 text-xs">
                        <div className="flex items-center text-gray-400">
                          <User className="w-3 h-3 mr-1" />
                          {script.author}
                        </div>
                        <div className="flex items-center text-gray-400">
                          <Calendar className="w-3 h-3 mr-1" />
                          {script.version}
                        </div>
                        {script.educational_value && (
                          <div className="flex items-center text-gray-400">
                            <Star className="w-3 h-3 mr-1" />
                            {Array.from({ length: script.educational_value }, (_, i) => (
                              <span key={i} className="text-yellow-400">★</span>
                            ))}
                          </div>
                        )}
                        {script.risk_level && (
                          <div className="flex items-center">
                            <span className={`px-2 py-1 rounded text-xs font-bold ${
                              script.risk_level === 'HIGH' ? 'bg-red-600 text-white' :
                              script.risk_level === 'MEDIUM' ? 'bg-yellow-600 text-black' : 
                              'bg-green-600 text-white'
                            }`}>
                              {script.risk_level}
                            </span>
                          </div>
                        )}
                      </div>

                      {/* Tags */}
                      {script.tags && script.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {script.tags.slice(0, 3).map((tag, index) => (
                            <span key={index} className="px-2 py-1 bg-gray-700 text-cyan-400 text-xs rounded flex items-center">
                              <Tag className="w-2 h-2 mr-1" />
                              {tag}
                            </span>
                          ))}
                          {script.tags.length > 3 && (
                            <span className="px-2 py-1 bg-gray-700 text-gray-400 text-xs rounded">
                              +{script.tags.length - 3} más
                            </span>
                          )}
                        </div>
                      )}

                      {/* Execute Button */}
                      <Button
                        onClick={() => setSelectedScript(script)}
                        className="w-full bg-green-600 hover:bg-green-700 text-white"
                      >
                        <Play className="w-4 h-4 mr-2" />
                        Ejecutar Script
                      </Button>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Scripts;
