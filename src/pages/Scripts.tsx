
import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Terminal, Play, Eye, Shield, Globe, Wrench, Users, Search, Brain, Clock, Smartphone } from "lucide-react";
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
          description: "Arsenal ofensivo avanzado y técnicas de penetración",
          icon: "terminal",
          script_count: 12
        },
        {
          id: "blue",
          name: "Blue Team",
          description: "Herramientas defensivas, monitoreo y análisis forense",
          icon: "shield",
          script_count: 8
        },
        {
          id: "purple",
          name: "Purple Team",
          description: "Ejercicios coordinados de ataque y defensa con MITRE ATT&CK",
          icon: "users",
          script_count: 4
        },
        {
          id: "osint",
          name: "OSINT",
          description: "Inteligencia de fuentes abiertas y perfilado avanzado",
          icon: "globe", 
          script_count: 2
        },
        {
          id: "forensics",
          name: "Análisis Forense",
          description: "Herramientas de investigación digital y análisis de evidencia",
          icon: "search",
          script_count: 5
        },
        {
          id: "mobile",
          name: "Mobile Stinger",
          description: "Herramientas móviles para Android y testing wireless",
          icon: "smartphone",
          script_count: 3
        },
        {
          id: "insight",
          name: "BOFA Insight",
          description: "Sistema de recomendaciones inteligentes y análisis de uso",
          icon: "brain",
          script_count: 2
        },
        {
          id: "timewarp",
          name: "TimeWarp",
          description: "Reproducción y análisis de sesiones de seguridad",
          icon: "clock", 
          script_count: 1
        }
      ];
    }
  });

  const { data: scripts, isLoading: scriptsLoading } = useQuery<Script[]>({
    queryKey: ['scripts', selectedModule],
    queryFn: async (): Promise<Script[]> => {
      if (!selectedModule) return [];
      
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
            description: "Herramienta de descubrimiento pasivo para SSIDs fantasma y redes ocultas",
            category: "recon",
            author: "@descambiado", 
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "reverse_dns_flood",
            description: "Test de resistencia pasiva con solicitudes DNS inversas masivas",
            category: "recon",
            author: "@descambiado",
            version: "1.0", 
            last_updated: "2025-06-18"
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
        "red": [
          {
            name: "ad_enum_visualizer",
            description: "Enumeración de Active Directory con visualización tipo BloodHound",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "bypass_uac_tool",
            description: "Simulador educativo de técnicas de bypass UAC en Windows",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "reverse_shell_polyglot",
            description: "Generador de reverse shells en múltiples lenguajes y protocolos",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "c2_simulator",
            description: "Simulador de infraestructura Command & Control para entrenamiento",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "ai_payload_mutator",
            description: "Generador adaptativo de shellcode con técnicas de mutación AI", 
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "post_exploit_enum",
            description: "Herramienta de enumeración post-explotación para evaluación completa",
            category: "red", 
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "kerberoast_scanner",
            description: "Simulador de ataques Kerberoasting para evaluación de cuentas de servicio AD",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "av_evasion_engine",
            description: "Motor avanzado de evasión antivirus para ofuscación de payload",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "dns_txt_exfil",
            description: "Herramienta de exfiltración DNS TXT para simulación de extracción encubierta",
            category: "red",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "reverse_shell_generator",
            description: "Generador avanzado de shells reversas multiplataforma",
            category: "red",
            author: "@descambiado",
            version: "1.0", 
            last_updated: "2025-06-17"
          }
        ],
        "blue": [
          {
            name: "ioc_matcher",
            description: "Análisis de Indicadores de Compromiso en archivos y logs del sistema",
            category: "blue",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "defense_break_replicator",
            description: "Simulador de comportamiento de malware para entrenar sistemas defensivos",
            category: "blue",
            author: "@descambiado", 
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "auth_log_parser",
            description: "Herramienta de análisis de logs de autenticación para monitoreo de seguridad",
            category: "blue",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "siem_alert_simulator",
            description: "Simulador avanzado de alertas SIEM para entrenamiento de equipos azules",
            category: "blue",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "log_baseliner",
            description: "Herramienta de análisis conductual y detección de anomalías en logs",
            category: "blue",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
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
        "purple": [
          {
            name: "purple_attack_orchestrator",
            description: "Orquestador avanzado de equipos purple para ejercicios coordinados",
            category: "purple",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "mitre_attack_runner",
            description: "Ejecutor del framework MITRE ATT&CK para validación defensiva Purple Team",
            category: "purple",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          }
        ],
        "osint": [
          {
            name: "multi_vector_osint",
            description: "Script OSINT que realiza ataques de contexto usando múltiples plataformas",
            category: "osint",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
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
        "forensics": [
          {
            name: "mft_parser",
            description: "Analizador de Master File Table (MFT) para investigación forense Windows",
            category: "forensics",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "browser_history_extractor",
            description: "Extractor de historial de navegadores para análisis forense",
            category: "forensics",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "volatility_launcher",
            description: "Wrapper automatizado de Volatility para análisis de memoria RAM",
            category: "forensics",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          }
        ],
        "mobile": [
          {
            name: "android_network_mapper",
            description: "Mapeador de redes Android compatible con Termux",
            category: "mobile",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "wifi_dos_tool",
            description: "Herramienta educativa de testing WiFi para Android",
            category: "mobile",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "mobile_payload_dropper",
            description: "Generador de payloads móviles con códigos QR",
            category: "mobile",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          }
        ],
        "insight": [
          {
            name: "skill_analyzer",
            description: "Analizador de habilidades y recomendador de prácticas personalizadas",
            category: "insight",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          },
          {
            name: "coverage_mapper",
            description: "Mapeador de cobertura Red/Blue/Purple con visualización radial",
            category: "insight",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
          }
        ],
        "timewarp": [
          {
            name: "session_recorder",
            description: "Grabador y reproductor de sesiones de seguridad para entrenamiento",
            category: "timewarp",
            author: "@descambiado",
            version: "1.0",
            last_updated: "2025-06-18"
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
          <h1 className="text-3xl font-bold text-cyan-400 mb-2">BOFA Extended Systems v2.0</h1>
          <p className="text-gray-300">Ecosistema completo de ciberseguridad - Red, Blue, Purple Team + Forensics + Mobile + AI</p>
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
                        <CardDescription className="text-gray-300">{module.script_count} herramientas disponibles</CardDescription>
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
