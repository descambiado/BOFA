
import { ScriptConfig } from '@/types/script';

// Script configurations based on actual YAML files
export const scriptConfigs: Record<string, ScriptConfig[]> = {
  "red": [
    {
      name: "supply_chain_scanner",
      display_name: "Supply Chain Security Scanner",
      description: "🔗 Mapea y analiza cadenas de suministro de software completas para detectar vulnerabilidades y riesgos",
      category: "red",
      subcategory: "supply_chain",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      risk_level: "LOW",
      impact_level: "LOW",
      educational_value: 5,
      tags: ["supply-chain", "dependencies", "vulnerabilities", "sbom", "software-composition"],
      parameters: {
        project_path: {
          type: "directory",
          description: "Ruta del proyecto a escanear",
          required: true,
          default: "./"
        },
        scan_depth: {
          type: "select",
          description: "Profundidad del escaneo",
          required: false,
          options: ["shallow", "deep", "comprehensive"],
          default: "deep"
        },
        include_dev_deps: {
          type: "boolean",
          description: "Incluir dependencias de desarrollo",
          required: false,
          default: true
        },
        output_format: {
          type: "select",
          description: "Formato de salida",
          required: false,
          options: ["json", "xml", "csv", "spdx"],
          default: "json"
        }
      },
      requirements: ["python3", "requests", "json"],
      features: [
        "🔗 Mapeo completo de cadena de suministro",
        "📦 Soporte para múltiples gestores de paquetes",
        "🚨 Detección de vulnerabilidades conocidas",
        "🔍 Análisis de integridad de paquetes"
      ]
    },
    {
      name: "cloud_native_attack_simulator",
      display_name: "Cloud Native Attack Simulator",
      description: "☁️ Simula ataques específicos a contenedores, Kubernetes y arquitecturas serverless",
      category: "red",
      subcategory: "cloud_security",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      risk_level: "HIGH",
      impact_level: "HIGH",
      educational_value: 5,
      tags: ["kubernetes", "docker", "containers", "serverless", "cloud-native"],
      parameters: {
        target_type: {
          type: "select",
          description: "Tipo de objetivo cloud native",
          required: true,
          options: ["kubernetes", "docker", "serverless", "comprehensive"],
          default: "kubernetes"
        },
        attack_scenarios: {
          type: "multiselect",
          description: "Escenarios de ataque a simular",
          required: false,
          options: ["container_escape", "privilege_escalation", "lateral_movement", "data_extraction", "resource_hijacking"],
          default: "container_escape"
        },
        intensity_level: {
          type: "select",
          description: "Intensidad del ataque simulado",
          required: false,
          options: ["low", "medium", "high", "extreme"],
          default: "medium"
        }
      }
    },
    {
      name: "ghost_scanner",
      display_name: "Ghost Scanner",
      description: "Escaneo sigiloso de red sin ARP con TTL y MAC randomization",
      category: "red",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-19",
      risk_level: "MEDIUM",
      impact_level: "MEDIUM",
      educational_value: 5,
      parameters: {
        target: {
          type: "string",
          description: "Rango de red a escanear (ej: 192.168.1.0)",
          required: true
        },
        delay: {
          type: "number",
          description: "Delay entre escaneos para sigilo",
          required: false,
          default: 0.5
        }
      }
    },
    {
      name: "reverse_shell_polyglot",
      display_name: "Reverse Shell Polyglot Generator",
      description: "Genera reverse shells en múltiples lenguajes y formatos",
      category: "red",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-18",
      risk_level: "MEDIUM",
      impact_level: "MEDIUM",
      educational_value: 5,
      parameters: {
        lhost: {
          type: "string",
          description: "IP address del listener",
          required: true
        },
        lport: {
          type: "number",
          description: "Puerto del listener",
          required: true
        },
        encoded: {
          type: "boolean",
          description: "Incluir variantes codificadas",
          required: false,
          default: false
        }
      }
    }
  ],
  "blue": [
    {
      name: "ai_threat_hunter",
      display_name: "AI-Powered Threat Hunter",
      description: "🤖 Detecta amenazas usando machine learning local y correlación de eventos con MITRE ATT&CK",
      category: "blue",
      subcategory: "threat_hunting",
      author: "@descambiado",
      version: "2.0",
      last_updated: "2025-01-20",
      risk_level: "LOW",
      impact_level: "LOW",
      educational_value: 5,
      tags: ["ai", "ml", "threat-hunting", "mitre-attack", "anomaly-detection"],
      parameters: {
        log_file: {
          type: "file",
          description: "Archivo de logs a analizar (JSON/CSV)",
          required: true
        },
        anomaly_threshold: {
          type: "number",
          description: "Umbral de anomalía (0.0-1.0)",
          required: false,
          default: 0.7,
          min: 0.0,
          max: 1.0
        },
        mitre_filter: {
          type: "select",
          description: "Filtrar por técnicas MITRE específicas",
          required: false,
          options: ["all", "T1003", "T1055", "T1059", "T1070", "T1082", "T1105", "T1190", "T1566"],
          default: "all"
        }
      },
      features: [
        "🤖 Machine Learning local para detección de anomalías",
        "🎯 Mapeo automático con MITRE ATT&CK Framework",
        "🔍 Pattern matching avanzado con regex",
        "📊 Análisis temporal y de comportamiento"
      ]
    },
    {
      name: "zero_trust_validator",
      display_name: "Zero Trust Validator",
      description: "🛡️ Valida implementaciones Zero Trust reales. Micro-segmentación, least privilege, identity verification",
      category: "blue",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      risk_level: "LOW",
      impact_level: "LOW",
      educational_value: 5,
      parameters: {
        environment: {
          type: "select",
          description: "Entorno a validar",
          required: true,
          options: ["production", "staging", "development"]
        },
        scope: {
          type: "select",
          description: "Alcance de la validación",
          required: false,
          options: ["network", "identity", "device", "all"],
          default: "all"
        }
      }
    },
    {
      name: "log_guardian",
      display_name: "Log Guardian",
      description: "Sistema avanzado de monitoreo de logs y detección de amenazas",
      category: "blue",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-16",
      parameters: {
        config: {
          type: "file",
          description: "Archivo de configuración JSON",
          required: false
        }
      }
    },
    {
      name: "auth_log_parser",
      display_name: "Auth Log Parser",
      description: "Advanced authentication log analysis tool for security monitoring and threat detection",
      category: "blue",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-17",
      parameters: {
        log_file: {
          type: "file",
          description: "Archivo de log de autenticación",
          required: true
        }
      }
    },
    {
      name: "ioc_matcher",
      display_name: "IOC Matcher",
      description: "Análisis de Indicadores de Compromiso en archivos y logs",
      category: "blue",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-18",
      parameters: {
        file: {
          type: "file",
          description: "Archivo para calcular y comparar hashes",
          required: false
        },
        log: {
          type: "file",
          description: "Archivo de log para analizar",
          required: false
        },
        text: {
          type: "string",
          description: "Texto para analizar directamente",
          required: false
        }
      }
    }
  ],
  "purple": [
    {
      name: "quantum_crypto_analyzer",
      display_name: "Quantum-Safe Crypto Analyzer",
      description: "🔮 Evalúa la resistencia criptográfica ante computación cuántica y genera planes de migración",
      category: "purple",
      subcategory: "cryptography",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      risk_level: "LOW",
      impact_level: "LOW",
      educational_value: 5,
      tags: ["quantum", "cryptography", "post-quantum", "migration"],
      parameters: {
        analysis_type: {
          type: "select",
          description: "Tipo de análisis a realizar",
          required: true,
          options: ["code", "network", "certificate", "comprehensive"],
          default: "comprehensive"
        },
        target_file: {
          type: "file",
          description: "Archivo de código fuente a analizar",
          required: false
        },
        target_host: {
          type: "string",
          description: "Host para análisis de red (ej: google.com)",
          required: false
        },
        target_port: {
          type: "number",
          description: "Puerto para análisis SSL/TLS",
          required: false,
          default: 443,
          min: 1,
          max: 65535
        }
      }
    },
    {
      name: "threat_emulator",
      display_name: "Threat Emulator",
      description: "Simula comportamiento de amenazas reales de forma ética para entrenamiento",
      category: "purple",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-19",
      parameters: {
        threat: {
          type: "select",
          description: "Tipo de amenaza a simular",
          required: false,
          options: ["apt", "ransomware", "insider", "all"],
          default: "apt"
        }
      }
    },
    {
      name: "purple_attack_orchestrator",
      display_name: "Purple Attack Orchestrator",
      description: "Advanced purple team orchestrator for coordinated red vs blue training exercises",
      category: "purple",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-18",
      parameters: {
        scenario: {
          type: "select",
          description: "Escenario de ataque",
          required: false,
          options: ["credential_harvest", "apt", "insider", "ransomware"],
          default: "apt"
        },
        speed: {
          type: "number",
          description: "Multiplicador de velocidad",
          required: false,
          default: 1.0
        }
      }
    }
  ],
  "osint": [
    {
      name: "iot_security_mapper",
      display_name: "IoT/OT Security Mapper",
      description: "🏭 Descubre y evalúa dispositivos IoT/OT expuestos usando Shodan y análisis de protocolos industriales",
      category: "osint",
      subcategory: "iot_discovery",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      risk_level: "MEDIUM",
      impact_level: "HIGH",
      educational_value: 5,
      tags: ["iot", "ot", "shodan", "industrial", "scada"],
      parameters: {
        search_query: {
          type: "string",
          description: "Query de búsqueda Shodan",
          required: false,
          default: "port:502,1883,47808,20000"
        },
        target_protocols: {
          type: "multiselect",
          description: "Protocolos industriales a buscar",
          required: false,
          options: ["modbus", "mqtt", "bacnet", "dnp3", "iec61850", "opcua", "coap"]
        },
        max_results: {
          type: "number",
          description: "Máximo número de resultados",
          required: false,
          default: 100,
          min: 10,
          max: 1000
        }
      }
    },
    {
      name: "multi_vector_osint",
      display_name: "Multi-Vector OSINT",
      description: "Revolutionary multi-vector OSINT tool for comprehensive target profiling",
      category: "osint",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-17",
      parameters: {
        email: {
          type: "string",
          description: "Email objetivo",
          required: false
        },
        name: {
          type: "string",
          description: "Nombre del objetivo",
          required: false
        },
        surname: {
          type: "string",
          description: "Apellido del objetivo",
          required: false
        },
        format: {
          type: "select",
          description: "Formato de salida",
          required: false,
          options: ["json", "html"],
          default: "json"
        }
      }
    },
    {
      name: "social_profile_mapper",
      display_name: "Social Profile Mapper",
      description: "Herramienta OSINT para descubrimiento de perfiles sociales públicos",
      category: "osint",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-16",
      parameters: {
        username: {
          type: "string",
          description: "Nombre de usuario a buscar",
          required: true
        },
        variations: {
          type: "boolean",
          description: "Incluir variaciones del username",
          required: false,
          default: false
        }
      }
    },
    {
      name: "public_email_validator",
      display_name: "Public Email Validator & Breach Checker",
      description: "Verifica emails con HaveIBeenPwned y valida dominios públicamente",
      category: "osint",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-19",
      parameters: {
        emails: {
          type: "string",
          description: "Emails a verificar (separados por comas)",
          required: true,
          example: "test@example.com,user@domain.org"
        },
        verbose: {
          type: "boolean",
          description: "Modo verbose",
          required: false,
          default: false
        }
      }
    },
    {
      name: "telegram_user_scraper",
      display_name: "Telegram User Scraper (OSINT)",
      description: "Extrae información de usuarios de grupos públicos de Telegram",
      category: "osint",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-19",
      parameters: {
        group: {
          type: "string",
          description: "Identificador del grupo de Telegram",
          required: true,
          example: "@crypto_signals"
        },
        export: {
          type: "select",
          description: "Formato de exportación",
          required: false,
          options: ["json", "csv"],
          default: "json"
        }
      }
    },
    {
      name: "github_repo_leak_detector",
      display_name: "GitHub Repository Leak Detector",
      description: "Detecta secretos (API keys, tokens) en repositorios públicos de GitHub",
      category: "osint",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-19",
      parameters: {
        queries: {
          type: "string",
          description: "Términos de búsqueda (separados por comas)",
          required: true,
          example: "api key,password,config"
        },
        max_repos: {
          type: "number",
          description: "Máximo repositorios por búsqueda",
          required: false,
          default: 5,
          max: 20
        }
      }
    }
  ],
  "malware": [
    {
      name: "malware_analyzer",
      display_name: "Malware Analyzer",
      description: "🔍 Analizador educativo de malware con técnicas de análisis estático avanzado",
      category: "malware",
      subcategory: "static_analysis",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      risk_level: "LOW",
      impact_level: "LOW",
      educational_value: 5,
      tags: ["malware", "static-analysis", "forensics", "threat-hunting"],
      parameters: {
        file_path: {
          type: "file",
          description: "Archivo a analizar",
          required: true,
          accepted_types: [".py", ".js", ".sh", ".ps1", ".bat", ".txt"]
        },
        analysis_depth: {
          type: "select",
          description: "Profundidad del análisis",
          required: false,
          options: ["basic", "standard", "deep"],
          default: "standard"
        },
        output_format: {
          type: "select",
          description: "Formato de salida",
          required: false,
          options: ["json", "html", "text"],
          default: "json"
        },
        include_context: {
          type: "boolean",
          description: "Incluir contexto de las coincidencias",
          required: false,
          default: true
        }
      }
    }
  ],
  "social": [
    {
      name: "social_engineer_toolkit",
      display_name: "Social Engineering Toolkit (Educativo)",
      description: "🎭 Herramientas educativas para concienciación sobre ingeniería social y phishing",
      category: "social",
      subcategory: "awareness_training",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      risk_level: "LOW",
      impact_level: "LOW",
      educational_value: 5,
      tags: ["social-engineering", "phishing", "awareness", "training"],
      parameters: {
        target_name: {
          type: "string",
          description: "Nombre del objetivo (simulación)",
          required: true,
          default: "Usuario Ejemplo"
        },
        target_role: {
          type: "select",
          description: "Rol del objetivo",
          required: false,
          options: ["employee", "manager", "executive", "hr", "finance", "admin", "it"],
          default: "employee"
        },
        scenario_type: {
          type: "select",
          description: "Tipo de escenario",
          required: false,
          options: ["it_support", "bank_security", "survey", "delivery", "government"],
          default: "it_support"
        }
      }
    }
  ],
  "study": [
    {
      name: "ctf_flag_planner",
      display_name: "CTF Flag Planner",
      description: "Permite crear escenarios CTF con banderas y puntuación para labs personalizados",
      category: "study",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-19",
      parameters: {
        create: {
          type: "boolean",
          description: "Crear CTF con desafíos predefinidos",
          required: false,
          default: false
        },
        export: {
          type: "string",
          description: "Directorio de exportación del CTF",
          required: false
        },
        flag: {
          type: "string",
          description: "Bandera a enviar",
          required: false
        },
        team: {
          type: "string",
          description: "Nombre del equipo",
          required: false
        }
      }
    }
  ]
};

export const getScriptsByCategory = (category: string): ScriptConfig[] => {
  return scriptConfigs[category] || [];
};

export const getAllScripts = (): ScriptConfig[] => {
  return Object.values(scriptConfigs).flat();
};

export const getScriptByName = (name: string): ScriptConfig | undefined => {
  return getAllScripts().find(script => script.name === name);
};

export const getScriptCount = (): number => {
  return getAllScripts().length;
};

export const getScriptCountByCategory = (category: string): number => {
  return scriptConfigs[category]?.length || 0;
};

export const getNewScripts2025 = (): ScriptConfig[] => {
  return getAllScripts().filter(script => script.last_updated === "2025-01-20");
};
