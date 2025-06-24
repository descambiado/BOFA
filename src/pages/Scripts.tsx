
import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Terminal, Play, Eye, Shield, Globe, Wrench, Users, Search, Brain, Clock, Smartphone, Zap, Lock, Link } from "lucide-react";
import { ScriptExecutor } from "@/components/ScriptExecutor";
import { ScriptAlert } from "@/components/ScriptAlert";

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
  impact_level?: string;
  educational_value?: number;
}

const moduleIcons = {
  recon: <Eye className="w-6 h-6" />,
  exploit: <Terminal className="w-6 h-6" />,
  osint: <Globe className="w-6 h-6" />,
  blue: <Shield className="w-6 h-6" />,
  purple: <Users className="w-6 h-6" />,
  malware: <Wrench className="w-6 h-6" />,
  red: <Terminal className="w-6 h-6" />,
  forensics: <Search className="w-6 h-6" />,
  insight: <Brain className="w-6 h-6" />,
  timewarp: <Clock className="w-6 h-6" />,
  mobile: <Smartphone className="w-6 h-6" />
};

const Scripts = () => {
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [selectedScript, setSelectedScript] = useState<Script | null>(null);

  const { data: modules, isLoading: modulesLoading } = useQuery<Module[]>({
    queryKey: ['modules'],
    queryFn: async (): Promise<Module[]> => {
      return [
        {
          id: "recon",
          name: "Reconocimiento",
          description: "Herramientas de descubrimiento y enumeración de redes",
          icon: "eye",
          script_count: 4
        },
        {
          id: "red", 
          name: "Red Team",
          description: "Arsenal ofensivo avanzado y técnicas de penetración + Supply Chain + Cloud Native",
          icon: "terminal",
          script_count: 18
        },
        {
          id: "blue",
          name: "Blue Team", 
          description: "Herramientas defensivas, AI threat hunting, Zero Trust validation y análisis forense",
          icon: "shield",
          script_count: 15
        },
        {
          id: "purple",
          name: "Purple Team",
          description: "Ejercicios coordinados + Quantum-Safe Crypto Analysis + Behavioral Biometrics",
          icon: "users",
          script_count: 10
        },
        {
          id: "forensics",
          name: "Análisis Forense",
          description: "Investigación digital avanzada + Deepfake Detection Engine + Timeline Analysis",
          icon: "search",
          script_count: 12
        },
        {
          id: "mobile",
          name: "Mobile Stinger",
          description: "Herramientas móviles para Android y testing wireless",
          icon: "smartphone", 
          script_count: 5
        },
        {
          id: "insight",
          name: "BOFA Insight",
          description: "Sistema de recomendaciones inteligentes con AI y análisis de uso",
          icon: "brain",
          script_count: 5
        },
        {
          id: "timewarp",
          name: "TimeWarp",
          description: "Reproducción y análisis de sesiones de seguridad",
          icon: "clock",
          script_count: 2
        },
        {
          id: "osint",
          name: "OSINT",
          description: "Inteligencia de fuentes abiertas + IoT Security Mapping + Threat Intelligence",
          icon: "globe",
          script_count: 10
        }
      ];
    }
  });

  const { data: scripts, isLoading: scriptsLoading } = useQuery<Script[]>({
    queryKey: ['scripts', selectedModule],
    queryFn: async (): Promise<Script[]> => {
      if (!selectedModule) return [];
      
      const scriptData: { [key: string]: Script[] } = {
        "red": [
          {
            name: "ad_enum_visualizer",
            description: "Genera visualizaciones tipo BloodHound de entornos Active Directory",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18",
            impact_level: "LOW",
            educational_value: 5
          },
          {
            name: "bypass_uac_tool",
            description: "Simula técnicas de bypass UAC para entrenamiento defensivo",
            category: "red", 
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18",
            impact_level: "LOW",
            educational_value: 5
          },
          {
            name: "reverse_shell_polyglot",
            description: "Genera reverse shells en múltiples lenguajes y formatos",
            category: "red",
            author: "@descambiado", 
            version: "1.0",
            last_updated: "2025-06-18",
            impact_level: "MEDIUM",
            educational_value: 5
          },
          {
            name: "c2_simulator",
            description: "Simula infraestructura Command & Control para entrenamiento",
            category: "red",
            author: "@descambiado",
            version: "1.0", 
            last_updated: "2025-06-18",
            impact_level: "MEDIUM",
            educational_value: 5
          },
          {
            name: "ghost_scanner",
            description: "Escaneo sigiloso de red sin ARP con TTL y MAC randomization",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-19", 
            impact_level: "MEDIUM",
            educational_value: 5
          },
          // 🚀 NUEVOS 2025
          {
            name: "supply_chain_scanner",
            description: "🔗 Mapea cadenas de suministro completas - NPM, PyPI, Maven. Detecta vulnerabilidades y riesgos post-SolarWinds",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-01-20",
            impact_level: "LOW",
            educational_value: 5
          },
          {
            name: "cloud_native_attack_simulator", 
            description: "☁️ Simula ataques a contenedores, Kubernetes y serverless. Container escape, privilege escalation, lateral movement",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-01-20",
            impact_level: "HIGH",  
            educational_value: 5
          }
        ],
        "blue": [
          {
            name: "ioc_matcher",
            description: "Análisis de Indicadores de Compromiso en archivos y logs",
            category: "blue",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18",
            impact_level: "LOW",
            educational_value: 5
          },
          {
            name: "log_timeline_builder", 
            description: "Genera línea de tiempo visual con eventos clave desde logs del sistema",
            category: "blue",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-19",
            impact_level: "LOW",
            educational_value: 5
          },
          // 🚀 NUEVOS 2025
          {
            name: "ai_threat_hunter",
            description: "🤖 ML local + MITRE ATT&CK. Detecta 0-days, anomalías temporales y comportamiento malicioso con IA",
            category: "blue", 
            author: "@descambiado",
            version: "2.0",
            last_updated: "2025-01-20", 
            impact_level: "LOW",
            educational_value: 5
          },
          {
            name: "zero_trust_validator",
            description: "🛡️ Valida implementaciones Zero Trust reales. Micro-segmentación, least privilege, identity verification",
            category: "blue",
            author: "@descambiado", 
            version: "1.0",
            last_updated: "2025-01-20",
            impact_level: "LOW", 
            educational_value: 5
          }
        ],
        "purple": [
          {
            name: "threat_emulator",
            description: "Simula comportamiento de amenazas reales de forma ética para entrenamiento",
            category: "purple",
            author: "@descambiado",
            version: "1.0", 
            last_updated: "2025-06-19",
            impact_level: "LOW",
            educational_value: 5
          },
          // 🚀 NUEVOS 2025
          {
            name: "quantum_crypto_analyzer",
            description: "🔮 Evalúa resistencia ante computación cuántica. Audita RSA, ECDSA. Genera planes de migración post-cuántica",
            category: "purple",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-01-20",
            impact_level: "LOW",
            educational_value: 5
          }
        ],
        "forensics": [
          {
            name: "memory_dump_analyzer",
            description: "Análisis forense de volcados de memoria para detectar malware y artefactos",
            category: "forensics",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-19",
            impact_level: "LOW", 
            educational_value: 5
          },
          // 🚀 NUEVOS 2025
          {
            name: "deepfake_detection_engine",
            description: "🎭 Detecta contenido multimedia generado por IA. Análisis facial, temporal y artefactos de compresión",
            category: "forensics",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-01-20",
            impact_level: "MEDIUM",
            educational_value: 5
          }
        ],
        "osint": [
          {
            name: "telegram_user_scraper",
            description: "Extrae información de usuarios de grupos públicos de Telegram",
            category: "osint",
            author: "@descambiado",
            version: "1.0", 
            last_updated: "2025-06-19",
            impact_level: "MEDIUM",
            educational_value: 5
          },
          {
            name: "public_email_validator",
            description: "Verifica emails con HaveIBeenPwned y valida dominios públicamente",
            category: "osint",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-19",
            impact_level: "LOW", 
            educational_value: 5
          },
          {
            name: "github_repo_leak_detector",
            description: "Detecta secretos (API keys, tokens) en repositorios públicos de GitHub",
            category: "osint",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-19",
            impact_level: "MEDIUM",
            educational_value: 5
          },
          // 🚀 NUEVOS 2025
          {
            name: "iot_security_mapper",
            description: "🏭 Descubre dispositivos IoT/OT expuestos via Shodan. Analiza protocolos industriales y evalúa seguridad",
            category: "osint",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-01-20",
            impact_level: "MEDIUM",
            educational_value: 5
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
          <h1 className="text-3xl font-bold text-cyan-400 mb-2">BOFA Extended Systems v2.5.0 🚀</h1>
          <p className="text-gray-300">
            <span className="text-cyan-400 font-semibold">INNOVACIÓN 2025:</span> AI Threat Hunting, Quantum-Safe Crypto, Supply Chain Security, Zero Trust Validation, Deepfake Detection, Cloud Native Attacks, IoT Security Mapping
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <span className="px-3 py-1 bg-cyan-600 text-white text-xs rounded-full">🤖 AI/ML Integration</span>
            <span className="px-3 py-1 bg-purple-600 text-white text-xs rounded-full">🔮 Post-Quantum Ready</span>
            <span className="px-3 py-1 bg-red-600 text-white text-xs rounded-full">🔗 Supply Chain Security</span>
            <span className="px-3 py-1 bg-blue-600 text-white text-xs rounded-full">🛡️ Zero Trust Validation</span>
            <span className="px-3 py-1 bg-green-600 text-white text-xs rounded-full">☁️ Cloud Native Attacks</span>
            <span className="px-3 py-1 bg-orange-600 text-white text-xs rounded-full">🎭 Deepfake Detection</span>
            <span className="px-3 py-1 bg-indigo-600 text-white text-xs rounded-full">🏭 IoT Security Mapping</span>
          </div>
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
                  className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all cursor-pointer transform hover:scale-105"
                  onClick={() => setSelectedModule(module.id)}
                >
                  <CardHeader>
                    <div className="flex items-center space-x-3">
                      <div className="text-cyan-400">
                        {moduleIcons[module.id as keyof typeof moduleIcons] || <Terminal className="w-6 h-6" />}
                      </div>
                      <div>
                        <CardTitle className="text-cyan-400">{module.name}</CardTitle>
                        <CardDescription className="text-gray-300">
                          {module.script_count} herramientas disponibles
                          {(module.id === 'red' || module.id === 'blue' || module.id === 'purple' || module.id === 'forensics' || module.id === 'osint') && (
                            <span className="ml-2 px-2 py-1 bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-xs rounded font-bold animate-pulse">
                              ✨ ACTUALIZADO 2025
                            </span>
                          )}
                        </CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-gray-300 mb-4">{module.description}</p>
                    <Button variant="outline" className="w-full border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black">
                      Explorar Módulo
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
                  <p className="text-gray-400 mt-4">Cargando herramientas...</p>
                </div>
              ) : (
                scripts?.map((script) => (
                  <Card key={script.name} className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all">
                    <CardHeader>
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <CardTitle className="text-cyan-400 flex items-center space-x-2">
                            <span>{script.name}</span>
                            {script.last_updated === "2025-01-20" && (
                              <span className="px-2 py-1 bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-xs rounded font-bold animate-pulse">
                                ✨ NUEVO 2025
                              </span>
                            )}
                          </CardTitle>
                          <CardDescription className="text-gray-300 mt-2">{script.description}</CardDescription>
                          
                          <div className="mt-4">
                            <ScriptAlert script={script} />
                          </div>
                        </div>
                        <Button 
                          size="sm"
                          onClick={() => setSelectedScript(script)}
                          className={`ml-4 ${
                            script.last_updated === "2025-01-20" 
                              ? "bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-700 hover:to-purple-700" 
                              : "bg-cyan-600 hover:bg-cyan-700"
                          }`}
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
                        {script.last_updated === "2025-01-20" && (
                          <span className="text-cyan-400 font-semibold">🚀 Tecnología 2025</span>
                        )}
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
