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
      // Mock data with updated counts for new scripts
      return [
        {
          id: "recon",
          name: "Reconocimiento",
          description: "Herramientas de descubrimiento y enumeración de redes",
          icon: "eye",
          script_count: 6
        },
        {
          id: "exploit", 
          name: "Explotación",
          description: "Generadores de payloads y exploits avanzados",
          icon: "terminal",
          script_count: 4
        },
        {
          id: "osint",
          name: "OSINT",
          description: "Inteligencia de fuentes abiertas y perfilado",
          icon: "globe", 
          script_count: 3
        },
        {
          id: "blue",
          name: "Blue Team",
          description: "Herramientas defensivas y análisis de logs",
          icon: "shield",
          script_count: 3
        },
        {
          id: "malware",
          name: "Análisis Malware", 
          description: "Herramientas de análisis estático y dinámico",
          icon: "wrench",
          script_count: 2
        }
      ];
    }
  });

  const { data: scripts, isLoading: scriptsLoading } = useQuery<Script[]>({
    queryKey: ['scripts', selectedModule],
    queryFn: async (): Promise<Script[]> => {
      if (!selectedModule) return [];
      
      // Mock data with all the new scripts
      const scriptData: { [key: string]: Script[] } = {
        "recon": [
          {
            name: "port_slayer",
            description: "Escáner de puertos avanzado con detección de servicios",
            category: "recon",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          },
          {
            name: "wifi_shadow_mapper", 
            description: "Revolutionary passive discovery tool for phantom SSIDs and hidden networks",
            category: "recon",
            author: "@descambiado", 
            version: "1.0",
            last_updated: "2025-06-17"
          },
          {
            name: "reverse_dns_flood",
            description: "Test de resistencia pasiva con solicitudes DNS inversas masivas",
            category: "recon",
            author: "@descambiado",
            version: "1.0", 
            last_updated: "2025-06-17"
          },
          {
            name: "web_discover",
            description: "Herramienta de descubrimiento web con fuzzing avanzado",
            category: "recon",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          }
        ],
        "exploit": [
          {
            name: "ai_payload_mutator",
            description: "Revolutionary adaptive shellcode generator with AI-powered mutation techniques", 
            category: "exploit",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          },
          {
            name: "post_exploit_enum",
            description: "Advanced post-exploitation enumeration tool for comprehensive system assessment",
            category: "exploit", 
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          },
          {
            name: "mitre_attack_runner",
            description: "MITRE ATT&CK framework runner for Purple Team defensive validation and testing",
            category: "exploit",
            author: "@descambiado", 
            version: "1.0",
            last_updated: "2025-06-17"
          },
          {
            name: "reverse_shell_generator",
            description: "Generador avanzado de shells reversas multiplataforma",
            category: "exploit",
            author: "@descambiado",
            version: "1.0", 
            last_updated: "2025-06-17"
          }
        ],
        "osint": [
          {
            name: "multi_vector_osint",
            description: "Script OSINT que hace un ataque de contexto usando múltiples plataformas",
            category: "osint",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          },
          {
            name: "social_profile_mapper", 
            description: "Mapeo avanzado de perfiles sociales y correlación de identidades",
            category: "osint",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          }
        ],
        "blue": [
          {
            name: "defense_break_replicator",
            description: "Revolutionary malware behavior simulator for training defense systems",
            category: "blue",
            author: "@descambiado", 
            version: "1.0",
            last_updated: "2025-06-17"
          },
          {
            name: "auth_log_parser",
            description: "Advanced authentication log analysis tool for security monitoring and threat detection",
            category: "blue",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          },
          {
            name: "log_guardian",
            description: "Sistema de monitoreo y análisis de logs en tiempo real",
            category: "blue", 
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          }
        ],
        "malware": [
          {
            name: "malware_analyzer",
            description: "Analizador estático de malware con detección de patrones",
            category: "malware",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-17"
          }
        ]
      };
      
      return scriptData[selectedModule] || [];
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
