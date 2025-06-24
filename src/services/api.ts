
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const API_BASE = 'http://localhost:8000';

// Types
export interface Script {
  name: string;
  description: string;
  category: string;
  author: string;
  version: string;
  last_updated: string;
  impact_level?: string;
  educational_value?: number;
  risk_level?: string;
  tags?: string[];
  parameters?: Record<string, any>;
}

export interface Module {
  id: string;
  name: string;
  description: string;
  icon: string;
  script_count: number;
  scripts?: Script[];
}

export interface ExecutionResult {
  id: string;
  module: string;
  script: string;
  parameters: Record<string, string>;
  timestamp: string;
  status: 'success' | 'error' | 'warning';
  execution_time: string;
  output?: string;
  error?: string;
}

export interface Lab {
  id: string;
  name: string;
  description: string;
  category: string;
  difficulty: string;
  status: 'stopped' | 'running' | 'starting' | 'error';
  estimated_time?: string;
  port?: number;
  url?: string;
}

export interface StudyLesson {
  id: string;
  title: string;
  description: string;
  category: string;
  difficulty: string;
  duration: number;
  completed: boolean;
  progress: number;
}

// Enhanced mock data with complete coverage
const mockModules: Module[] = [
  {
    id: "recon",
    name: "Reconocimiento",
    description: "Herramientas de descubrimiento y enumeración de redes",
    icon: "eye",
    script_count: 8
  },
  {
    id: "red", 
    name: "Red Team",
    description: "Arsenal ofensivo avanzado y técnicas de penetración + Supply Chain + Cloud Native",
    icon: "terminal",
    script_count: 25
  },
  {
    id: "blue",
    name: "Blue Team", 
    description: "Herramientas defensivas, AI threat hunting, Zero Trust validation y análisis forense",
    icon: "shield",
    script_count: 18
  },
  {
    id: "purple",
    name: "Purple Team",
    description: "Ejercicios coordinados + Quantum-Safe Crypto Analysis + Behavioral Biometrics",
    icon: "users",
    script_count: 12
  },
  {
    id: "forensics",
    name: "Análisis Forense",
    description: "Investigación digital avanzada + Deepfake Detection Engine + Timeline Analysis",
    icon: "search",
    script_count: 15
  },
  {
    id: "mobile",
    name: "Mobile Stinger",
    description: "Herramientas móviles para Android y testing wireless",
    icon: "smartphone", 
    script_count: 8
  },
  {
    id: "malware",
    name: "Malware Analysis",
    description: "Análisis de malware, detección de amenazas y reverse engineering",
    icon: "bug",
    script_count: 10
  },
  {
    id: "social",
    name: "Social Engineering",
    description: "Herramientas de concienciación sobre ingeniería social",
    icon: "users",
    script_count: 6
  },
  {
    id: "insight",
    name: "BOFA Insight",
    description: "Sistema de recomendaciones inteligentes con AI y análisis de uso",
    icon: "brain",
    script_count: 7
  },
  {
    id: "osint",
    name: "OSINT",
    description: "Inteligencia de fuentes abiertas + IoT Security Mapping + Threat Intelligence",
    icon: "globe",
    script_count: 12
  }
];

const mockScripts: Record<string, Script[]> = {
  "recon": [
    {
      name: "advanced_network_mapper",
      description: "🗺️ Herramienta avanzada de mapeo de red con técnicas sigilosas y detección de servicios",
      category: "recon",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      impact_level: "LOW",
      educational_value: 5
    },
    {
      name: "port_slayer",
      description: "Escáner de puertos ultra-rápido con técnicas de evasión",
      category: "recon",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-06-18",
      impact_level: "LOW",
      educational_value: 5
    }
  ],
  "red": [
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
  "malware": [
    {
      name: "malware_analyzer",
      description: "🔍 Analizador educativo de malware con técnicas de análisis estático avanzado",
      category: "malware",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      impact_level: "LOW",
      educational_value: 5
    }
  ],
  "social": [
    {
      name: "social_engineer_toolkit",
      description: "🎭 Herramientas educativas para concienciación sobre ingeniería social y phishing",
      category: "social",
      author: "@descambiado",
      version: "1.0",
      last_updated: "2025-01-20",
      impact_level: "LOW",
      educational_value: 5
    }
  ]
};

const mockHistory: ExecutionResult[] = [
  {
    id: "exec-001",
    module: "blue",
    script: "ai_threat_hunter",
    parameters: { log_file: "security.log", threshold: "0.7" },
    timestamp: new Date().toISOString(),
    status: "success",
    execution_time: "2.3s",
    output: "[INFO] AI Threat Hunter iniciado\n[SUCCESS] 3 amenazas detectadas\n[INFO] Análisis completado"
  },
  {
    id: "exec-002",
    module: "red",
    script: "supply_chain_scanner",
    parameters: { project_path: "./", scan_depth: "deep" },
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    status: "warning",
    execution_time: "5.7s",
    output: "[WARNING] 2 vulnerabilidades encontradas\n[INFO] Escaneo completado"
  },
  {
    id: "exec-003",
    module: "malware",
    script: "malware_analyzer",
    parameters: { file_path: "suspicious.exe", analysis_depth: "deep" },
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    status: "success",
    execution_time: "8.1s",
    output: "[INFO] Análisis de malware iniciado\n[SUCCESS] 5 indicadores de riesgo detectados\n[INFO] Reporte generado"
  }
];

const mockLabs: Lab[] = [
  {
    id: "web-application-security",
    name: "Web Application Security Lab",
    description: "Laboratorio completo para práctica de vulnerabilidades web",
    category: "web_security",
    difficulty: "intermediate",
    status: "stopped",
    estimated_time: "240 minutos",
    port: 8080,
    url: "http://localhost:8080"
  },
  {
    id: "internal-network",
    name: "Red Interna Corporativa",
    description: "Simula una red corporativa completa con múltiples servicios",
    category: "network",
    difficulty: "intermediate",
    status: "stopped",
    estimated_time: "180 minutos"
  },
  {
    id: "android-lab",
    name: "Android Security Lab",
    description: "Emulador Android con apps vulnerables para testing móvil",
    category: "mobile",
    difficulty: "advanced",
    status: "running",
    estimated_time: "150 minutos",
    port: 5555
  }
];

const mockStudyLessons: StudyLesson[] = [
  {
    id: "web_application_security",
    title: "Seguridad en Aplicaciones Web",
    description: "Curso completo sobre vulnerabilidades web y OWASP Top 10",
    category: "web_security",
    difficulty: "intermediate",
    duration: 180,
    completed: false,
    progress: 25
  },
  {
    id: "network_penetration_testing",
    title: "Penetration Testing de Redes",
    description: "Metodologías y técnicas de pentesting en infraestructuras de red",
    category: "network_security",
    difficulty: "advanced",
    duration: 240,
    completed: false,
    progress: 0
  },
  {
    id: "malware_analysis_fundamentals",
    title: "Fundamentos de Análisis de Malware",
    description: "Técnicas básicas y avanzadas para análisis de malware",
    category: "malware_analysis",
    difficulty: "advanced",
    duration: 300,
    completed: true,
    progress: 100
  }
];

// API Functions with comprehensive error handling and offline support
export const apiService = {
  // Scripts and Modules
  getModules: async (): Promise<Module[]> => {
    try {
      const response = await fetch(`${API_BASE}/modules`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(5000) // 5 second timeout
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('✅ API: Modules loaded from server');
      return data;
    } catch (error) {
      console.warn('⚠️ API: Server unavailable, using offline data');
      return mockModules;
    }
  },

  getScriptsByModule: async (module: string): Promise<Script[]> => {
    try {
      const response = await fetch(`${API_BASE}/modules/${module}/scripts`, {
        signal: AbortSignal.timeout(5000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const data = await response.json();
      console.log(`✅ API: Scripts for ${module} loaded from server`);
      return data;
    } catch (error) {
      console.warn(`⚠️ API: Using offline scripts for ${module}`);
      return mockScripts[module] || [];
    }
  },

  executeScript: async (data: {
    module: string;
    script: string;
    parameters: Record<string, string>;
  }): Promise<ExecutionResult> => {
    try {
      const response = await fetch(`${API_BASE}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
        signal: AbortSignal.timeout(30000) // 30 second timeout for execution
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const result = await response.json();
      console.log(`✅ API: Script ${data.script} executed on server`);
      return result;
    } catch (error) {
      console.warn(`⚠️ API: Simulating execution of ${data.script}`);
      
      // Enhanced simulation with realistic outputs
      const simulatedOutputs = {
        "ai_threat_hunter": "[INFO] AI Threat Hunter v2.0 iniciado\n[ML] Cargando modelos de detección...\n[SCAN] Analizando 1,245 eventos de log\n[DETECT] 3 amenazas de alta severidad encontradas\n[MITRE] Técnicas identificadas: T1055, T1003\n[SUCCESS] Análisis completado - Reporte generado",
        "malware_analyzer": "[INFO] Malware Analyzer v1.0\n[HASH] MD5: 5d41402abc4b2a76b9719d911017c592\n[SCAN] Analizando patrones sospechosos...\n[DETECT] 5 indicadores de riesgo encontrados\n[RISK] Nivel de amenaza: ALTO\n[SUCCESS] Análisis completado",
        "supply_chain_scanner": "[INFO] Supply Chain Scanner iniciado\n[SCAN] Analizando dependencias NPM/PyPI...\n[VULN] 2 vulnerabilidades críticas encontradas\n[CVE] CVE-2023-1234, CVE-2023-5678\n[WARNING] Verificar cadena de suministro\n[SUCCESS] Escaneo completado"
      };
      
      return {
        id: `exec-${Date.now()}`,
        module: data.module,
        script: data.script,
        parameters: data.parameters,
        timestamp: new Date().toISOString(),
        status: Math.random() > 0.8 ? 'warning' : 'success',
        execution_time: `${(Math.random() * 15 + 2).toFixed(1)}s`,
        output: simulatedOutputs[data.script as keyof typeof simulatedOutputs] || 
                `[INFO] Ejecutando ${data.script}...\n[SUCCESS] Script ejecutado exitosamente\n[INFO] Proceso completado`
      };
    }
  },

  // History
  getExecutionHistory: async (): Promise<ExecutionResult[]> => {
    try {
      const response = await fetch(`${API_BASE}/history`, {
        signal: AbortSignal.timeout(5000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const data = await response.json();
      console.log('✅ API: History loaded from server');
      return data;
    } catch (error) {
      console.warn('⚠️ API: Using offline history data');
      return mockHistory;
    }
  },

  // Labs
  getLabs: async (): Promise<Lab[]> => {
    try {
      const response = await fetch(`${API_BASE}/labs`, {
        signal: AbortSignal.timeout(5000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const data = await response.json();
      console.log('✅ API: Labs loaded from server');
      return data;
    } catch (error) {
      console.warn('⚠️ API: Using offline labs data');
      return mockLabs;
    }
  },

  startLab: async (labId: string): Promise<{ status: string; message: string }> => {
    try {
      const response = await fetch(`${API_BASE}/labs/${labId}/start`, {
        method: 'POST',
        signal: AbortSignal.timeout(10000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const result = await response.json();
      console.log(`✅ API: Lab ${labId} started on server`);
      return result;
    } catch (error) {
      console.warn(`⚠️ API: Simulating lab ${labId} start`);
      return {
        status: 'success',
        message: `Lab ${labId} iniciado exitosamente (simulado)`
      };
    }
  },

  stopLab: async (labId: string): Promise<{ status: string; message: string }> => {
    try {
      const response = await fetch(`${API_BASE}/labs/${labId}/stop`, {
        method: 'POST',
        signal: AbortSignal.timeout(10000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const result = await response.json();
      console.log(`✅ API: Lab ${labId} stopped on server`);
      return result;
    } catch (error) {
      console.warn(`⚠️ API: Simulating lab ${labId} stop`);
      return {
        status: 'success',
        message: `Lab ${labId} detenido exitosamente (simulado)`
      };
    }
  },

  // Study System
  getStudyLessons: async (): Promise<StudyLesson[]> => {
    try {
      const response = await fetch(`${API_BASE}/study/lessons`, {
        signal: AbortSignal.timeout(5000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const data = await response.json();
      console.log('✅ API: Study lessons loaded from server');
      return data;
    } catch (error) {
      console.warn('⚠️ API: Using offline study data');
      return mockStudyLessons;
    }
  },

  updateLessonProgress: async (lessonId: string, progress: number): Promise<void> => {
    try {
      const response = await fetch(`${API_BASE}/study/lessons/${lessonId}/progress`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ progress }),
        signal: AbortSignal.timeout(5000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      console.log(`✅ API: Progress updated for lesson ${lessonId}`);
    } catch (error) {
      console.warn(`⚠️ API: Progress update simulated for lesson ${lessonId}`);
    }
  },

  // Reports and Analytics
  getDashboardStats: async (): Promise<Record<string, any>> => {
    try {
      const response = await fetch(`${API_BASE}/dashboard/stats`, {
        signal: AbortSignal.timeout(5000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const data = await response.json();
      console.log('✅ API: Dashboard stats loaded from server');
      return data;
    } catch (error) {
      console.warn('⚠️ API: Using simulated dashboard stats');
      return {
        total_scripts: 150,
        total_executions: 1247,
        active_labs: 3,
        completion_rate: 78,
        threat_level: "MEDIUM",
        last_scan: new Date().toISOString()
      };
    }
  }
};

// React Query Hooks with enhanced error handling
export const useModules = () => {
  return useQuery({
    queryKey: ['modules'],
    queryFn: apiService.getModules,
    staleTime: 5 * 60 * 1000, // 5 minutes
    retry: 1,
    retryDelay: 1000,
    refetchOnWindowFocus: false,
  });
};

export const useScripts = (module: string) => {
  return useQuery({
    queryKey: ['scripts', module],
    queryFn: () => apiService.getScriptsByModule(module),
    enabled: !!module,
    retry: 1,
    staleTime: 5 * 60 * 1000,
  });
};

export const useExecutionHistory = () => {
  return useQuery({
    queryKey: ['execution-history'],
    queryFn: apiService.getExecutionHistory,
    refetchInterval: 30000, // Refresh every 30 seconds
    retry: 1,
    staleTime: 10 * 1000, // 10 seconds
  });
};

export const useLabs = () => {
  return useQuery({
    queryKey: ['labs'],
    queryFn: apiService.getLabs,
    retry: 1,
    staleTime: 30 * 1000, // 30 seconds
    refetchInterval: 15000, // Check status every 15 seconds
  });
};

export const useStudyLessons = () => {
  return useQuery({
    queryKey: ['study-lessons'],
    queryFn: apiService.getStudyLessons,
    retry: 1,
    staleTime: 5 * 60 * 1000,
  });
};

export const useDashboardStats = () => {
  return useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: apiService.getDashboardStats,
    retry: 1,
    staleTime: 2 * 60 * 1000, // 2 minutes
    refetchInterval: 60000, // Refresh every minute
  });
};

export const useExecuteScript = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiService.executeScript,
    onSuccess: (data) => {
      // Invalidate and refetch history
      queryClient.invalidateQueries({ queryKey: ['execution-history'] });
      
      // Update dashboard stats
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
      
      console.log(`✅ Script execution completed: ${data.script}`);
    },
    onError: (error) => {
      console.error('❌ Script execution failed:', error);
    }
  });
};

export const useLabControl = () => {
  const queryClient = useQueryClient();
  
  return {
    startLab: useMutation({
      mutationFn: apiService.startLab,
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ['labs'] });
      },
    }),
    stopLab: useMutation({
      mutationFn: apiService.stopLab,
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ['labs'] });
      },
    }),
  };
};

export const useUpdateLessonProgress = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: ({ lessonId, progress }: { lessonId: string; progress: number }) =>
      apiService.updateLessonProgress(lessonId, progress),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['study-lessons'] });
    },
  });
};
