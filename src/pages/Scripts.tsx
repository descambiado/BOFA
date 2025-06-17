
import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Terminal, Play, Eye, Shield, Globe, Wrench } from "lucide-react";
import { ScriptExecutor } from "@/components/ScriptExecutor";

interface Module {
  id: string;
  name: string;
  description: string;
  icon: string;
  script_count: number;
}

interface Script {
  name: string;
  description: string;
  category: string;
  author: string;
  version: string;
  last_updated: string;
}

const moduleIcons = {
  recon: <Eye className="w-6 h-6" />,
  exploit: <Terminal className="w-6 h-6" />,
  osint: <Globe className="w-6 h-6" />,
  blue: <Shield className="w-6 h-6" />,
  malware: <Wrench className="w-6 h-6" />,
};

const Scripts = () => {
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [selectedScript, setSelectedScript] = useState<Script | null>(null);

  const { data: modules, isLoading: modulesLoading } = useQuery<Module[]>({
    queryKey: ['modules'],
    queryFn: async (): Promise<Module[]> => {
      const response = await fetch('http://localhost:8000/modules');
      if (!response.ok) throw new Error('Failed to fetch modules');
      return response.json();
    }
  });

  const { data: scripts, isLoading: scriptsLoading } = useQuery<Script[]>({
    queryKey: ['scripts', selectedModule],
    queryFn: async (): Promise<Script[]> => {
      if (!selectedModule) return [];
      const response = await fetch(`http://localhost:8000/scripts/${selectedModule}`);
      if (!response.ok) throw new Error('Failed to fetch scripts');
      return response.json();
    },
    enabled: !!selectedModule
  });

  if (selectedScript) {
    return (
      <ScriptExecutor 
        module={selectedModule!}
        script={selectedScript}
        onBack={() => setSelectedScript(null)}
      />
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-cyan-400 mb-2">Scripts de Ciberseguridad</h1>
          <p className="text-gray-300">Ejecuta herramientas profesionales desde el navegador</p>
        </div>

        {!selectedModule ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {modulesLoading ? (
              <div className="col-span-full text-center py-12">
                <div className="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto"></div>
                <p className="text-gray-400 mt-4">Cargando módulos...</p>
              </div>
            ) : (
              modules?.map((module) => (
                <Card 
                  key={module.id} 
                  className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all cursor-pointer"
                  onClick={() => setSelectedModule(module.id)}
                >
                  <CardHeader>
                    <div className="flex items-center space-x-3">
                      <div className="text-cyan-400">
                        {moduleIcons[module.id as keyof typeof moduleIcons] || <Terminal className="w-6 h-6" />}
                      </div>
                      <div>
                        <CardTitle className="text-cyan-400">{module.name}</CardTitle>
                        <CardDescription className="text-gray-300">{module.script_count} scripts disponibles</CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-gray-300 mb-4">{module.description}</p>
                    <Button variant="outline" className="w-full border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black">
                      Ver Scripts
                    </Button>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        ) : (
          <div>
            <div className="mb-6">
              <Button 
                variant="outline" 
                onClick={() => setSelectedModule(null)}
                className="border-gray-600 text-gray-300 hover:bg-gray-700"
              >
                ← Volver a Módulos
              </Button>
            </div>

            <div className="grid gap-4">
              {scriptsLoading ? (
                <div className="text-center py-12">
                  <div className="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto"></div>
                  <p className="text-gray-400 mt-4">Cargando scripts...</p>
                </div>
              ) : (
                scripts?.map((script) => (
                  <Card key={script.name} className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all">
                    <CardHeader>
                      <div className="flex justify-between items-start">
                        <div>
                          <CardTitle className="text-cyan-400">{script.name}</CardTitle>
                          <CardDescription className="text-gray-300 mt-2">{script.description}</CardDescription>
                        </div>
                        <Button 
                          size="sm"
                          onClick={() => setSelectedScript(script)}
                          className="bg-cyan-600 hover:bg-cyan-700"
                        >
                          <Play className="w-4 h-4 mr-2" />
                          Ejecutar
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-4 text-sm text-gray-400">
                        <span>Autor: {script.author}</span>
                        <span>Versión: {script.version}</span>
                        <span>Actualizado: {script.last_updated}</span>
                      </div>
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
