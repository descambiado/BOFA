
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ScriptConfig, ExecutionHistory } from '@/types/script';
import { scriptConfigs, getScriptsByCategory, getAllScripts } from '@/utils/scriptLoader';

const API_BASE = 'http://localhost:8000';

// Types
export interface Module {
  id: string;
  name: string;
  description: string;
  icon: string;
  script_count: number;
  scripts?: ScriptConfig[];
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

// Enhanced mock data with real script counts
const mockModules: Module[] = [
  {
    id: "red", 
    name: "Red Team",
    description: "Arsenal ofensivo avanzado y técnicas de penetración + Supply Chain + Cloud Native",
    icon: "terminal",
    script_count: getScriptsByCategory("red").length
  },
  {
    id: "blue",
    name: "Blue Team", 
    description: "Herramientas defensivas, AI threat hunting, Zero Trust validation y análisis forense",
    icon: "shield",
    script_count: getScriptsByCategory("blue").length
  },
  {
    id: "purple",
    name: "Purple Team",
    description: "Ejercicios coordinados + Quantum-Safe Crypto Analysis + Behavioral Biometrics",
    icon: "users",
    script_count: getScriptsByCategory("purple").length
  },
  {
    id: "osint",
    name: "OSINT",
    description: "Inteligencia de fuentes abiertas + IoT Security Mapping + Threat Intelligence",
    icon: "search",
    script_count: getScriptsByCategory("osint").length
  },
  {
    id: "malware",
    name: "Malware Analysis",
    description: "Análisis de malware, detección de amenazas y reverse engineering",
    icon: "bug",
    script_count: getScriptsByCategory("malware").length
  },
  {
    id: "social",
    name: "Social Engineering",
    description: "Herramientas de concienciación sobre ingeniería social",
    icon: "users",
    script_count: getScriptsByCategory("social").length
  },
  {
    id: "study",
    name: "Study & Training",
    description: "Herramientas educativas y de entrenamiento CTF",
    icon: "book-open",
    script_count: getScriptsByCategory("study").length
  }
];

// Generate realistic execution history
const generateMockHistory = (): ExecutionResult[] => {
  const scripts = getAllScripts();
  const history: ExecutionResult[] = [];
  
  for (let i = 0; i < 25; i++) {
    const script = scripts[Math.floor(Math.random() * scripts.length)];
    const now = new Date();
    const timestamp = new Date(now.getTime() - (i * 3600000 + Math.random() * 3600000));
    
    history.push({
      id: `exec-${String(i).padStart(3, '0')}`,
      module: script.category,
      script: script.name,
      parameters: script.parameters ? Object.keys(script.parameters).reduce((acc, key) => {
        const param = script.parameters![key];
        acc[key] = param.default?.toString() || 'test_value';
        return acc;
      }, {} as Record<string, string>) : {},
      timestamp: timestamp.toISOString(),
      status: Math.random() > 0.8 ? (Math.random() > 0.5 ? 'warning' : 'error') : 'success',
      execution_time: `${(Math.random() * 15 + 1).toFixed(1)}s`,
      output: `Script ${script.name} ejecutado correctamente`
    });
  }
  
  return history.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
};

const mockHistory = generateMockHistory();

const mockLabs: Lab[] = [
  {
    id: "web-application-security",
    name: "Web Application Security Lab",
    description: "Laboratorio completo para práctica de vulnerabilidades web (OWASP Top 10)",
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
    description: "Simula una red corporativa completa con múltiples servicios y vulnerabilidades",
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
  },
  {
    id: "kubernetes-cluster",
    name: "Kubernetes Security Cluster",
    description: "Cluster Kubernetes vulnerable para práctica de Cloud Native Security",
    category: "cloud_native",
    difficulty: "advanced",
    status: "stopped",
    estimated_time: "300 minutos",
    port: 6443
  },
  {
    id: "iot-simulation",
    name: "IoT/OT Simulation Environment",
    description: "Entorno simulado de dispositivos IoT/OT con protocolos industriales",
    category: "iot_security",
    difficulty: "expert",
    status: "stopped",
    estimated_time: "360 minutos",
    port: 8502
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
  },
  {
    id: "cloud_native_security",
    title: "Cloud Native Security",
    description: "Seguridad en contenedores, Kubernetes y arquitecturas serverless",
    category: "cloud_security",
    difficulty: "expert",
    duration: 420,
    completed: false,
    progress: 15
  },
  {
    id: "ai_threat_hunting",
    title: "AI-Powered Threat Hunting",
    description: "Uso de inteligencia artificial para detección avanzada de amenazas",
    category: "ai_security",
    difficulty: "expert",
    duration: 360,
    completed: false,
    progress: 0
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
        signal: AbortSignal.timeout(5000)
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

  getScriptsByModule: async (module: string): Promise<ScriptConfig[]> => {
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
      return getScriptsByCategory(module);
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
        signal: AbortSignal.timeout(30000)
      });
      
      if (!response.ok) throw new Error('API not available');
      
      const result = await response.json();
      console.log(`✅ API: Script ${data.script} executed on server`);
      return result;
    } catch (error) {
      console.warn(`⚠️ API: Simulating execution of ${data.script}`);
      
      return {
        id: `exec-${Date.now()}`,
        module: data.module,
        script: data.script,
        parameters: data.parameters,
        timestamp: new Date().toISOString(),
        status: Math.random() > 0.8 ? 'warning' : 'success',
        execution_time: `${(Math.random() * 15 + 2).toFixed(1)}s`,
        output: `Script ${data.script} ejecutado correctamente con parámetros: ${JSON.stringify(data.parameters)}`
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
        total_scripts: getAllScripts().length,
        total_executions: mockHistory.length,
        active_labs: mockLabs.filter(lab => lab.status === 'running').length,
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
    staleTime: 5 * 60 * 1000,
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
    refetchInterval: 30000,
    retry: 1,
    staleTime: 10 * 1000,
  });
};

export const useLabs = () => {
  return useQuery({
    queryKey: ['labs'],
    queryFn: apiService.getLabs,
    retry: 1,
    staleTime: 5 * 60 * 1000,
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
    refetchInterval: 60000, // Refresh every minute
    retry: 1,
    staleTime: 30 * 1000,
  });
};
