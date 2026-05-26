
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ScriptConfig, ExecutionHistory } from '@/types/script';
import { APP_CONFIG } from '@/config/app';
import { toast } from 'sonner';

const API_BASE = APP_CONFIG.api.baseUrl;

// Authentication state
let currentToken: string | null = null;
let currentUser: any = null;

// Get auth headers
const getAuthHeaders = () => ({
  'Content-Type': 'application/json',
  ...(currentToken && { 'Authorization': `Bearer ${currentToken}` })
});

// Types
export interface Module {
  id: string;
  name: string;
  description: string;
  icon: string;
  script_count: number;
  recent_script_count?: number;
  scripts?: ScriptConfig[];
}

export interface ExecutionResult {
  id: string;
  run_id?: string;
  module: string;
  script: string;
  parameters: Record<string, string>;
  timestamp: string;
  status: 'success' | 'error' | 'warning';
  execution_time: string;
  output?: string;
  error?: string;
}

export interface RunEvent {
  id: string;
  run_id: string;
  scope_type: string;
  scope_id?: string;
  event_type: string;
  status?: string;
  message?: string;
  payload?: Record<string, any>;
  created_at: string;
}

export interface RunArtifactMetadata {
  step_id?: string;
  execution_id?: string;
  run_status?: string;
  step_status?: string;
  artifact_role?: string;
  previewable?: boolean;
  preview_mode?: "head" | "tail";
  content_type?: string;
  size_bytes?: number;
  partial?: boolean;
  downloadable?: boolean;
  download_reason?: string | null;
}

export interface RunArtifact {
  id: string;
  run_id: string;
  artifact_type: string;
  path: string;
  label?: string;
  metadata?: RunArtifactMetadata;
  created_at: string;
}

export interface RunArtifactPreview {
  run_id: string;
  artifact: RunArtifact;
  previewable: boolean;
  preview: string | null;
  truncated: boolean;
  preview_mode?: "head" | "tail";
  content_type?: string;
  size_bytes?: number;
  reason?: string | null;
}

export interface RunEvidenceArtifactCheck {
  artifact_id: string;
  artifact_type: string;
  included: boolean;
  verified: boolean;
  reason?: string | null;
  relative_path?: string | null;
  manifest_sha256?: string | null;
  bundle_entry_sha256?: string | null;
  bundle_match?: boolean;
  source_match?: boolean | null;
  source_reason?: string | null;
}

export interface RunEvidenceCanonicalFileCheck {
  name: string;
  verified: boolean;
  reason?: string | null;
  expected_sha256?: string | null;
  expected_size_bytes?: number | null;
  actual_sha256?: string | null;
  actual_size_bytes?: number | null;
}

export interface EvidencePublicKeyInfo {
  signing_algorithm: string;
  public_key_fingerprint: string;
  public_key_pem: string;
  path: string;
  trust_anchor?: string;
}

export interface RunEvidenceVerification {
  run_id: string;
  verified: boolean;
  export_timestamp: string;
  bundle_artifact: RunArtifact;
  manifest_artifact: RunArtifact;
  signature_artifact?: RunArtifact;
  public_key_artifact?: RunArtifact;
  bundle_sha256: string;
  manifest_sha256: string;
  manifest_file_sha256?: string;
  canonical_files: string[];
  missing_canonical_files: string[];
  canonical_file_checks?: RunEvidenceCanonicalFileCheck[];
  artifact_checks: RunEvidenceArtifactCheck[];
  artifact_count: number;
  included_count: number;
  verified_artifact_count: number;
  missing_count: number;
  warning_count: number;
  bundle_version?: string;
  signature_valid: boolean;
  integrity_valid: boolean;
  signing_algorithm?: string;
  public_key_fingerprint?: string;
  public_key_matches_server?: boolean | null;
  trust_mode?: string;
  signature_error?: string | null;
  manifest_sha_valid?: boolean;
  manifest_artifact_match?: boolean;
  signature_artifact_match?: boolean;
  public_key_artifact_match?: boolean;
}

export interface RunStep {
  id: string;
  run_id: string;
  step_type: string;
  step_key?: string;
  module?: string;
  script_name?: string;
  status: string;
  step_index: number;
  parameters?: Record<string, any>;
  started_at?: string;
  completed_at?: string;
  exit_code?: number;
  duration?: number;
  stdout_preview?: string;
  stderr_preview?: string;
  error_message?: string;
}

export interface RunLab {
  id: string;
  run_id: string;
  lab_id: string;
  status: string;
  container_id?: string;
  port?: number;
  started_at?: string;
  stopped_at?: string;
}

export interface RunSummary {
  id: string;
  run_type: string;
  source: string;
  status: string;
  target?: string;
  requested_action: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  parent_run_id?: string;
  metadata?: Record<string, any>;
  timeline_count?: number;
  step_count?: number;
  artifact_count?: number;
  lab_count?: number;
}

export interface RunDetail extends RunSummary {
  steps: RunStep[];
  labs: RunLab[];
  events: RunEvent[];
  artifacts: RunArtifact[];
}

export interface BountyWorkspace {
  id: string;
  user_id?: number;
  name: string;
  platform: string;
  program_handle: string;
  notes?: string;
  metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
  assets?: WorkspaceAsset[];
  imports?: WorkspaceImport[];
  snapshots?: WorkspaceSnapshot[];
  deltas?: SurfaceDelta[];
  graph?: BountyGraph;
  findings?: NoveltyFinding[];
  clusters?: FindingCluster[];
  review_queue?: ReviewQueueItem[];
  skills?: BountySkill[];
}

export interface WorkspaceAsset {
  id: string;
  workspace_id: string;
  asset_type: string;
  value: string;
  normalized_value: string;
  in_scope: boolean;
  source?: string;
  first_seen?: string;
  last_seen?: string;
  metadata?: Record<string, any>;
}

export interface WorkspaceImport {
  id: string;
  workspace_id: string;
  run_id?: string;
  import_type: string;
  source_label: string;
  source_path?: string;
  source_url?: string;
  content_format?: string;
  snapshot_id?: string;
  status: string;
  summary?: string;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface TargetGraphNode {
  id: string;
  workspace_id: string;
  node_type: string;
  normalized_key: string;
  value: string;
  first_seen?: string;
  last_seen?: string;
  metadata?: Record<string, any>;
}

export interface TargetGraphEdge {
  id: string;
  workspace_id: string;
  from_node_id: string;
  edge_type: string;
  to_node_id: string;
  first_seen?: string;
  last_seen?: string;
  metadata?: Record<string, any>;
}

export interface BountyGraph {
  nodes: TargetGraphNode[];
  edges: TargetGraphEdge[];
  assets: WorkspaceAsset[];
  imports: WorkspaceImport[];
}

export interface NoveltyFinding {
  id?: string;
  workspace_id?: string;
  fingerprint: string;
  title: string;
  category: 'what_changed' | 'what_is_weird' | 'worth_manual_time' | 'likely_duplicate' | string;
  novelty_score: number;
  duplicate_risk_score: number;
  confidence: number;
  status: string;
  rationale: string;
  primary_node_id?: string;
  run_id?: string;
  metadata?: Record<string, any>;
  created_at?: string;
}

export interface WorkspaceSnapshot {
  id: string;
  workspace_id: string;
  run_id?: string;
  snapshot_type: string;
  label?: string;
  source?: string;
  previous_snapshot_id?: string;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface SurfaceDelta {
  id: string;
  workspace_id: string;
  snapshot_id: string;
  previous_snapshot_id?: string;
  entity_type: string;
  entity_key: string;
  entity_label?: string;
  change_type: string;
  node_id?: string;
  asset_id?: string;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface FindingCluster {
  id: string;
  workspace_id: string;
  snapshot_id?: string;
  cluster_key: string;
  hypothesis: string;
  root_cause?: string;
  novelty_score: number;
  duplicate_risk_score: number;
  status: string;
  rationale?: string;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface ReviewQueueItem {
  cluster_id?: string;
  cluster_key: string;
  snapshot_id?: string;
  hypothesis: string;
  why_now: string;
  evidence: Array<Record<string, any>>;
  novelty_score: number;
  duplicate_risk_score: number;
  next_manual_step: string;
  report_candidate: boolean;
  finding_ids?: string[];
  finding_titles?: string[];
  root_cause?: string;
}

export interface BountySkill {
  skill_key: string;
  name: string;
  goal: string;
  scope: string;
  inputs?: string[];
  steps?: string[];
  heuristics?: string[];
  stop_conditions?: string[];
  artifacts?: string[];
  output_schema?: Record<string, any>;
  path?: string;
}

export interface SkillRunResult {
  workspace_id: string;
  run_id: string;
  skill_key: string;
  skill_name: string;
  goal?: string;
  latest_snapshot_id?: string;
  summary?: Record<string, any>;
  [key: string]: any;
}

export interface FlowSummary {
  id: string;
  name: string;
  description: string;
  steps_count: number;
}

export interface Lab {
  id: string;
  name: string;
  description: string;
  category: string;
  difficulty: string;
  status: 'stopped' | 'running' | 'starting' | 'error' | 'cancelling';
  estimated_time?: string;
  port?: number;
  url?: string;
  technologies?: string[];
  features?: string[];
  message?: string;
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

// Offline fallbacks used when the BOFA runtime is unavailable
const OFFLINE_MODULE_COUNT = 0;

const DEMO_EXECUTION_SEEDS: Array<{
  module: string;
  script: string;
  parameters: Record<string, string>;
  output: string;
}> = [
  {
    module: "bounty",
    script: "delta_recon",
    parameters: { workspace: "acme-demo", snapshot: "latest" },
    output: "Delta recon completed against latest snapshot.",
  },
  {
    module: "web",
    script: "surface_regression",
    parameters: { target: "https://demo.acme.test" },
    output: "Surface regression flagged new admin export route.",
  },
  {
    module: "recon",
    script: "subdomain_passive",
    parameters: { scope: "acme.test" },
    output: "Passive recon collected new external host candidates.",
  },
  {
    module: "reporting",
    script: "manual_handoff",
    parameters: { finding: "authz-admin-export" },
    output: "Generated analyst handoff notes and evidence pointers.",
  },
  {
    module: "blue",
    script: "auth_log_parser",
    parameters: { source: "demo-auth.log" },
    output: "Parsed authentication anomalies from sample logs.",
  },
];

const buildMockHistory = (): ExecutionResult[] => {
  return DEMO_EXECUTION_SEEDS.map((seed, index) => {
    const now = new Date();
    const timestamp = new Date(now.getTime() - index * 45 * 60 * 1000);
    const status: ExecutionResult["status"] = index === 3 ? "warning" : "success";

    return {
      id: `exec-${String(index + 1).padStart(3, "0")}`,
      module: seed.module,
      script: seed.script,
      parameters: seed.parameters,
      timestamp: timestamp.toISOString(),
      status,
      execution_time: `${(index + 2) * 1.3}s`,
      output: seed.output,
    };
  });
};

let mockHistoryPromise: Promise<ExecutionResult[]> | null = null;

const getMockHistory = () => {
  if (!mockHistoryPromise) {
    mockHistoryPromise = Promise.resolve(buildMockHistory());
  }
  return mockHistoryPromise;
};

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

// Database simulada para autenticación funcional
const mockUsers = [
  {
    id: 1,
    username: 'admin',
    password: 'admin123', // En producción sería hasheada
    role: 'admin',
    fullName: 'Administrador BOFA',
    email: 'admin@bofa.local',
    permissions: ['all']
  },
  {
    id: 2,
    username: 'redteam',
    password: 'red123',
    role: 'red_team',
    fullName: 'Red Team Operator',
    email: 'red@bofa.local',
    permissions: ['execute_red', 'view_history', 'manage_labs']
  },
  {
    id: 3,
    username: 'blueteam',
    password: 'blue123',
    role: 'blue_team',
    fullName: 'Blue Team Analyst',
    email: 'blue@bofa.local',
    permissions: ['execute_blue', 'view_history', 'view_reports']
  }
];

// JWT mock para funcionamiento real
const generateMockJWT = (user: any) => {
  const header = btoa(JSON.stringify({ typ: 'JWT', alg: 'HS256' }));
  const payload = btoa(JSON.stringify({ 
    sub: user.id,
    username: user.username,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 horas
  }));
  const signature = btoa(`mock_signature_${user.id}`);
  return `${header}.${payload}.${signature}`;
};

// Authentication service - Completamente funcional
export const authService = {
  login: async (username: string, password: string) => {
    await new Promise(resolve => setTimeout(resolve, 400));

    // 1) Intento real contra API
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        signal: AbortSignal.timeout(5000)
      });

      if (response.ok) {
        const data = await response.json();
        currentToken = data.access_token;
        currentUser = data.user;
        localStorage.setItem('bofa_token', currentToken);
        localStorage.setItem('bofa_user', JSON.stringify(currentUser));
        toast.success(`¡Bienvenido/a ${currentUser.username}! (API real)`);
        return { access_token: currentToken, token_type: 'bearer', user: currentUser };
      }
    } catch (e) {
      // Continuamos a fallback
    }

    // 2) Fallback mock completamente funcional
    try {
      const user = mockUsers.find(u => u.username === username && u.password === password);
      if (!user) throw new Error('Credenciales inválidas');

      const access_token = generateMockJWT(user);
      const userData = {
        id: user.id,
        username: user.username,
        role: user.role,
        fullName: user.fullName,
        email: user.email,
        permissions: user.permissions
      };

      currentToken = access_token;
      currentUser = userData;
      localStorage.setItem('bofa_token', currentToken);
      localStorage.setItem('bofa_user', JSON.stringify(currentUser));
      toast.success(`¡Bienvenido/a ${userData.fullName}! (modo demo)`);
      return { access_token, token_type: 'bearer', user: userData };
    } catch (error) {
      console.error('❌ LOGIN ERROR:', error);
      toast.error(error instanceof Error ? error.message : 'Error de autenticación');
      throw error;
    }
  },

  logout: () => {
    currentToken = null;
    currentUser = null;
    localStorage.removeItem('bofa_token');
    localStorage.removeItem('bofa_user');
    toast.info('Sesión cerrada');
  },

  getCurrentUser: () => currentUser,
  isAuthenticated: () => !!currentToken,
  initializeAuth: () => {
    const token = localStorage.getItem('bofa_token');
    const user = localStorage.getItem('bofa_user');
    if (token && user) {
      currentToken = token;
      try { currentUser = JSON.parse(user); } catch { localStorage.removeItem('bofa_token'); localStorage.removeItem('bofa_user'); }
    }
  }
};

// Initialize auth on load
authService.initializeAuth();

// API Functions with comprehensive error handling and offline support
export const apiService = {
  // Scripts and Modules
  getModules: async (): Promise<Module[]> => {
    try {
      const response = await fetch(`${API_BASE}/modules`, {
        method: 'GET',
        headers: getAuthHeaders(),
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
      throw new Error('BOFA runtime unavailable while loading modules');
    }
  },

  getScriptsByModule: async (module: string): Promise<ScriptConfig[]> => {
    const normalize = (scripts: any[]): ScriptConfig[] => {
      return scripts.map((s: any) => {
        const paramsArray = s.parameters || [];
        const paramMap = Array.isArray(paramsArray)
          ? paramsArray.reduce((acc: any, p: any) => {
              acc[p.name] = {
                type: (p.type === 'float' ? 'number' : p.type) || 'string',
                description: p.description || '',
                required: !!p.required,
                default: p.default,
                options: p.options,
                min: p.min,
                max: p.max,
                example: p.example,
              };
              return acc;
            }, {})
          : (paramsArray || {});
        const filePath = s.file_path as string | undefined;
        const slugFromPath = filePath ? filePath.split('/').pop()?.replace(/\.[^.]+$/, '') : undefined;
        return {
          name: s.id || slugFromPath || (s.name?.toLowerCase().replace(/[^a-z0-9]+/g, '_') ?? 'script'),
          display_name: s.display_name || s.name,
          description: s.description || '',
          category: module,
          author: s.author || 'Unknown',
          version: s.version || '1.0',
          last_updated: s.last_updated || new Date().toISOString().slice(0,10),
          is_recent: !!s.is_recent,
          risk_level: s.risk_level,
          impact_level: s.impact_level,
          educational_value: s.educational_value,
          tags: s.tags || [],
          parameters: paramMap,
        } as ScriptConfig;
      });
    };

    try {
      const response = await fetch(`${API_BASE}/modules/${module}/scripts`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
      if (!response.ok) throw new Error('API not available');
      const data = await response.json();
      console.log(`✅ API: Scripts for ${module} loaded from server`);
      return normalize(data);
    } catch (error) {
      console.warn(`⚠️ API: Using offline scripts for ${module}`);
      throw new Error(`BOFA runtime unavailable while loading scripts for ${module}`);
    }
  },

  // Ejecución real con control manual (start/poll/stop)
  startExecution: async (data: { module: string; script: string; parameters: Record<string, string>; }): Promise<{ execution_id: string; run_id: string }> => {
    if (!authService.isAuthenticated()) throw new Error('Debe autenticarse para ejecutar scripts');
    try {
      const response = await fetch(`${API_BASE}/execute`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(data),
        signal: AbortSignal.timeout(APP_CONFIG.api.timeout)
      });
      if (!response.ok) throw new Error('API not available');
      const result = await response.json();
      return { execution_id: result.execution_id, run_id: result.run_id || result.execution_id };
    } catch (error) {
      console.warn(`⚠️ API: Simulando inicio de ejecución de ${data.script}`);
      const id = `mock-${Date.now()}`;
      return { execution_id: id, run_id: id };
    }
  },

  getExecutionStatus: async (execution_id: string): Promise<any> => {
    try {
      const response = await fetch(`${API_BASE}/execute/${execution_id}`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(APP_CONFIG.api.timeout)
      });
      if (!response.ok) throw new Error('API not available');
      return await response.json();
    } catch (error) {
      // Fallback: devolver finalizado con éxito
      return {
        id: execution_id,
        status: 'success',
        output: 'Ejecución completada (simulada)'
      };
    }
  },

  stopExecution: async (execution_id: string): Promise<void> => {
    try {
      await fetch(`${API_BASE}/execute/${execution_id}/stop`, {
        method: 'POST',
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
    } catch (error) {
      // ignore
    }
  },

  // Historial
  getExecutionHistory: async (): Promise<ExecutionResult[]> => {
    try {
      const response = await fetch(`${API_BASE}/history`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
      if (!response.ok) throw new Error('API not available');
      const data = await response.json();
      console.log('✅ API: History loaded from server');
      return data;
    } catch (error) {
      console.warn('⚠️ API: Using offline history data');
      return await getMockHistory();
    }
  },

  getRuns: async (workspaceId?: string | null): Promise<RunSummary[]> => {
    try {
      const query = workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : '';
      const response = await fetch(`${API_BASE}/runs${query}`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
      if (!response.ok) throw new Error('API not available');
      return await response.json();
    } catch (error) {
      const mockHistory = await getMockHistory();
      return mockHistory.map((item) => ({
        id: item.id,
        run_type: 'script',
        source: 'demo',
        status: item.status,
        requested_action: 'execute_script',
        created_at: item.timestamp,
        metadata: {
          module: item.module,
          script: item.script,
          parameters: item.parameters,
        },
        step_count: 1,
        timeline_count: 2,
        artifact_count: item.output ? 1 : 0,
        lab_count: 0,
      }));
      }
    },

  getBountyWorkspaces: async (): Promise<BountyWorkspace[]> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) throw new Error('No se pudieron obtener los workspaces bounty');
    return await response.json();
  },

  createBountyWorkspace: async (payload: {
    name: string;
    platform: string;
    program_handle: string;
    notes?: string;
    metadata?: Record<string, any>;
  }): Promise<BountyWorkspace> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) throw new Error('No se pudo crear el workspace bounty');
    return await response.json();
  },

  getBountyWorkspace: async (workspaceId: string): Promise<BountyWorkspace> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error('No se pudo obtener el workspace bounty');
    return await response.json();
  },

  importBountyWorkspaceContent: async (
    workspaceId: string,
    payload: {
      import_type: string;
      source_label: string;
      content: string;
      content_format?: string;
      source_url?: string;
      source_path?: string;
      metadata?: Record<string, any>;
    },
  ): Promise<any> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/imports`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) throw new Error('No se pudo importar contenido bounty');
    return await response.json();
  },

  analyzeBountyWorkspace: async (workspaceId: string): Promise<{ workspace_id: string; run_id: string; summary: Record<string, any>; findings: NoveltyFinding[]; clusters?: FindingCluster[]; review_queue?: ReviewQueueItem[] }> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/analyze`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(20000)
    });
    if (!response.ok) throw new Error('No se pudo analizar el workspace bounty');
    return await response.json();
  },

  getBountyWorkspaceGraph: async (workspaceId: string): Promise<BountyGraph> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/graph`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error('No se pudo obtener el target graph');
    return await response.json();
  },

  getBountyWorkspaceSnapshots: async (workspaceId: string): Promise<WorkspaceSnapshot[]> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/snapshots`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error('No se pudieron obtener los snapshots del workspace');
    return await response.json();
  },

  getBountyWorkspaceDiffs: async (
    workspaceId: string,
    snapshotId?: string | null,
  ): Promise<{ workspace_id: string; snapshot_id?: string | null; snapshot: WorkspaceSnapshot | null; deltas: SurfaceDelta[] }> => {
    const query = snapshotId ? `?snapshot_id=${encodeURIComponent(snapshotId)}` : '';
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/diffs${query}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error('No se pudieron obtener los deltas del workspace');
    return await response.json();
  },

  getBountyWorkspaceLatestDiffs: async (
    workspaceId: string,
  ): Promise<{ workspace_id: string; snapshot_id?: string | null; snapshot: WorkspaceSnapshot | null; deltas: SurfaceDelta[] }> => {
    return apiService.getBountyWorkspaceDiffs(workspaceId);
  },

  getBountyWorkspaceFindings: async (workspaceId: string): Promise<NoveltyFinding[]> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/findings`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error('No se pudieron obtener los findings bounty');
    return await response.json();
  },

  getBountyWorkspaceReviewQueue: async (workspaceId: string, snapshotId?: string | null): Promise<{ workspace_id: string; snapshot_id?: string | null; items: ReviewQueueItem[] }> => {
    const query = snapshotId ? `?snapshot_id=${encodeURIComponent(snapshotId)}` : '';
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/review-queue${query}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error('No se pudo obtener la review queue');
    return await response.json();
  },

  exportBountyWorkspaceReviewQueue: async (workspaceId: string, snapshotId?: string | null): Promise<{ workspace_id: string; snapshot_id: string; run_id: string; item_count: number; artifacts: string[] }> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/review-queue/export`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ snapshot_id: snapshotId || null }),
      signal: AbortSignal.timeout(20000)
    });
    if (!response.ok) throw new Error('No se pudo exportar la review queue');
    return await response.json();
  },

  getBountySkills: async (): Promise<BountySkill[]> => {
    const response = await fetch(`${API_BASE}/bounty/skills`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) throw new Error('No se pudieron obtener las skills bounty');
    return await response.json();
  },

  runBountySkill: async (workspaceId: string, skillKey: string): Promise<SkillRunResult> => {
    const response = await fetch(`${API_BASE}/bounty/workspaces/${workspaceId}/skills/${skillKey}/run`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(20000)
    });
    if (!response.ok) throw new Error('No se pudo ejecutar la skill bounty');
    return await response.json();
  },

  getRun: async (runId: string): Promise<RunDetail> => {
    try {
      const response = await fetch(`${API_BASE}/runs/${runId}`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(8000)
      });
      if (!response.ok) throw new Error('No se pudo obtener el detalle del run');
      return await response.json();
    } catch (error) {
      return {
        id: runId,
        run_type: runId.startsWith('mock-flow') ? 'flow' : 'script',
        source: 'demo',
        status: 'running',
        target: 'demo-target',
        requested_action: runId.startsWith('mock-flow') ? 'execute_flow' : 'execute_script',
        created_at: new Date().toISOString(),
        metadata: {
          flow_id: runId.startsWith('mock-flow') ? 'demo-flow' : undefined,
        },
        steps: [],
        labs: [],
        events: [],
        artifacts: [],
      };
    }
  },

  getRunTimeline: async (runId: string): Promise<{ run_id: string; events: RunEvent[]; artifacts: RunArtifact[] }> => {
    const response = await fetch(`${API_BASE}/runs/${runId}/timeline`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) throw new Error('No se pudo obtener el timeline del run');
    return await response.json();
  },

  getRunArtifactPreview: async (runId: string, artifactId: string): Promise<RunArtifactPreview> => {
    try {
      const response = await fetch(`${API_BASE}/runs/${runId}/artifacts/${artifactId}/preview`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(8000)
      });
      if (!response.ok) throw new Error('No se pudo obtener el preview del artifact');
      return await response.json();
    } catch (error) {
      return {
        run_id: runId,
        artifact: {
          id: artifactId,
          run_id: runId,
          artifact_type: "unknown",
          path: "",
          created_at: new Date().toISOString(),
          metadata: {
            previewable: false,
            content_type: "text/plain",
          },
        },
        previewable: false,
        preview: null,
        truncated: false,
        preview_mode: "head",
        content_type: "text/plain",
        reason: "preview_unavailable_in_demo",
      };
    }
  },

  downloadRunArtifact: async (runId: string, artifactId: string): Promise<{ filename: string; demo?: boolean }> => {
    try {
      const response = await fetch(`${API_BASE}/runs/${runId}/artifacts/${artifactId}/download`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(20000)
      });
      if (!response.ok) throw new Error('No se pudo descargar el artifact');

      const blob = await response.blob();
      const contentDisposition = response.headers.get('Content-Disposition') || '';
      const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/i);
      const filename = filenameMatch?.[1] || `bofa_artifact_${artifactId}`;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      return { filename };
    } catch (error) {
      const preview = await apiService.getRunArtifactPreview(runId, artifactId);
      const content = preview.preview ?? JSON.stringify(preview, null, 2);
      const blob = new Blob([content], { type: preview.content_type || 'text/plain' });
      const url = URL.createObjectURL(blob);
      const filename = `${artifactId}_demo.txt`;
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      return { filename, demo: true };
    }
  },

  downloadRunExport: async (runId: string): Promise<{ filename: string; demo?: boolean }> => {
    try {
      const response = await fetch(`${API_BASE}/runs/${runId}/export`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(20000)
      });
      if (!response.ok) throw new Error('No se pudo exportar el bundle del run');

      const blob = await response.blob();
      const contentDisposition = response.headers.get('Content-Disposition') || '';
      const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/i);
      const filename = filenameMatch?.[1] || `bofa_evidence_${runId}.zip`;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      return { filename };
    } catch (error) {
      const run = await apiService.getRun(runId);
      const blob = new Blob([JSON.stringify(run, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const filename = `bofa_evidence_${runId}_demo.json`;
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      return { filename, demo: true };
    }
  },

  getEvidencePublicKey: async (): Promise<EvidencePublicKeyInfo> => {
    try {
      const response = await fetch(`${API_BASE}/evidence/public-key`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) throw new Error('No se pudo obtener la clave publica de evidencia');
      return await response.json();
    } catch (error) {
      return {
        signing_algorithm: 'Ed25519',
        public_key_fingerprint: 'demo-unavailable',
        public_key_pem: '-----BEGIN PUBLIC KEY-----\nDEMO\n-----END PUBLIC KEY-----\n',
        path: 'demo://evidence/public-key',
        trust_anchor: 'sha256:demo-unavailable',
      };
    }
  },

  verifyRunEvidenceExport: async (runId: string): Promise<RunEvidenceVerification> => {
    const response = await fetch(`${API_BASE}/runs/${runId}/export/verify`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(20000)
    });
    if (!response.ok) throw new Error('No se pudo verificar el evidence bundle');
    return await response.json();
  },

  cancelRun: async (runId: string): Promise<any> => {
    try {
      const response = await fetch(`${API_BASE}/runs/${runId}/cancel`, {
        method: 'POST',
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(8000)
      });
      if (!response.ok) throw new Error('No se pudo cancelar el run');
      return await response.json();
    } catch (error) {
      return { run_id: runId, status: 'cancelled', message: 'Run cancelado en modo demo' };
    }
  },

  retryRun: async (runId: string): Promise<any> => {
    try {
      const response = await fetch(`${API_BASE}/runs/${runId}/retry`, {
        method: 'POST',
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(8000)
      });
      if (!response.ok) throw new Error('No se pudo reintentar el run');
      return await response.json();
    } catch (error) {
      return { run_id: `retry-${runId}`, status: 'running', message: 'Retry lanzado en modo demo' };
    }
  },

  getFlows: async (): Promise<FlowSummary[]> => {
    try {
      const response = await fetch(`${API_BASE}/flows`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
      if (!response.ok) throw new Error('API not available');
      return await response.json();
    } catch (error) {
      return [
        {
          id: 'full_recon',
          name: 'full_recon',
          description: 'Recon completo sobre un target con descubrimiento, cabeceras, robots.txt y CVE lookup',
          steps_count: 4,
        },
        {
          id: 'vuln_triage',
          name: 'vuln_triage',
          description: 'Triaging rápido para findings y priorización operativa',
          steps_count: 3,
        },
        {
          id: 'blue_daily',
          name: 'blue_daily',
          description: 'Cadena defensiva diaria para revisar señales, resúmenes y correlación',
          steps_count: 4,
        },
      ];
    }
  },

  startFlow: async (flowId: string, target: string): Promise<{ run_id: string; status: string; message: string }> => {
    try {
      const response = await fetch(`${API_BASE}/runs`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          run_type: 'flow',
          source: 'ui',
          requested_action: 'execute_flow',
          target,
          metadata: {
            flow_id: flowId,
            target,
          },
        }),
        signal: AbortSignal.timeout(APP_CONFIG.api.timeout)
      });
      if (!response.ok) throw new Error('API not available');
      return await response.json();
    } catch (error) {
      return {
        run_id: `mock-flow-${Date.now()}`,
        status: 'running',
        message: `Flow ${flowId} iniciado en modo demo`,
      };
    }
  },

  // Labs
  getLabs: async (): Promise<Lab[]> => {
    try {
      const response = await fetch(`${API_BASE}/labs`, {
        headers: getAuthHeaders(),
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

  startLab: async (labId: string): Promise<{ status: string; message: string; run_id?: string; lab_run_id?: string; url?: string; port?: number }> => {
    try {
      const response = await fetch(`${API_BASE}/labs/${labId}/start`, {
        method: 'POST',
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) throw new Error('API not available');
      const result = await response.json();
      console.log(`✅ API: Lab ${labId} started on server`);
      return result;
    } catch (error) {
      console.warn(`⚠️ API: Simulating lab ${labId} start`);
      return { status: 'success', message: `Lab ${labId} iniciado exitosamente (simulado)`, run_id: `mock-lab-${Date.now()}` };
    }
  },

  stopLab: async (labId: string): Promise<{ status: string; message: string; run_id?: string; lab_run_id?: string }> => {
    try {
      const response = await fetch(`${API_BASE}/labs/${labId}/stop`, {
        method: 'POST',
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) throw new Error('API not available');
      const result = await response.json();
      console.log(`✅ API: Lab ${labId} stopped on server`);
      return result;
    } catch (error) {
      console.warn(`⚠️ API: Simulating lab ${labId} stop`);
      return { status: 'success', message: `Lab ${labId} detenido exitosamente (simulado)`, run_id: `mock-lab-stop-${Date.now()}` };
    }
  },

  // Study System
  getStudyLessons: async (): Promise<StudyLesson[]> => {
    try {
      const response = await fetch(`${API_BASE}/study/lessons`, {
        headers: getAuthHeaders(),
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
        headers: { ...getAuthHeaders() },
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
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
      if (!response.ok) throw new Error('API not available');
      const data = await response.json();
      console.log('API: Dashboard stats loaded from server');
      return data;
    } catch (error) {
      console.warn('API: Using simulated dashboard stats');
      const mockHistory = await getMockHistory();
      const activeLabs = mockLabs.filter(lab => lab.status === 'running').length;
      const totalExecutions = mockHistory.length;
      const successful = mockHistory.filter(item => item.status === 'success').length;
      const failed = mockHistory.filter(item => item.status !== 'success').length;
      const successRate = totalExecutions > 0 ? Number(((successful / totalExecutions) * 100).toFixed(1)) : 0;

      return {
        total_scripts: 0,
        total_executions: totalExecutions,
        active_labs: activeLabs,
        completion_rate: successRate,
        threat_level: "MEDIUM",
        last_scan: new Date().toISOString(),
        modules: OFFLINE_MODULE_COUNT,
        system_status: "demo",
        overview: {
          total_scripts: 0,
          modules: OFFLINE_MODULE_COUNT,
          scripts_updated_recently: 0,
          system_status: "demo",
          threat_level: "MEDIUM",
          last_scan: new Date().toISOString()
        },
        executions: {
          total_executions: totalExecutions,
          successful,
          failed,
          queued: 0,
          running: 0,
          success_rate: successRate
        },
        docker: {
          active_labs: activeLabs,
          containers_running: activeLabs
        },
        system: {
          cpu_percent: 0,
          memory_percent: 0,
          active_executions: 0,
          disk_free_gb: 0
        },
        queue: {
          queued: 0,
          running: 0,
          completed: totalExecutions,
          max_concurrent: APP_CONFIG.limits.maxConcurrentScripts
        },
        recent_activity: mockHistory.slice(0, 10).map(item => ({
          id: item.id,
          run_type: 'script',
          source: 'demo',
          status: item.status,
          target: item.script,
          requested_action: 'execute_script',
          created_at: item.timestamp,
          metadata: {
            module: item.module,
            script_name: item.script,
            output: item.output,
          },
        }))
      };
    }
  },

  // Scripts Library
  getScriptCatalog: async (): Promise<any[]> => {
    try {
      const response = await fetch(`${API_BASE}/scripts/catalog`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
      if (!response.ok) throw new Error('API not available');
      const data = await response.json();
      return data;
    } catch (error) {
      // Fallback: build minimal catalog from local YAML loader (sin código)
      throw new Error('BOFA runtime unavailable while loading the script catalog');
    }
  },

  getScriptCode: async (moduleId: string, scriptName: string): Promise<{ filename: string; language: string; content: string; lines: number; size: number; } > => {
    const response = await fetch(`${API_BASE}/scripts/${moduleId}/${scriptName}/code`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) throw new Error('No se pudo obtener el código del script');
    return await response.json();
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

export const useRuns = (workspaceId?: string | null) => {
  return useQuery({
    queryKey: ['runs', workspaceId ?? 'all'],
    queryFn: () => apiService.getRuns(workspaceId),
    refetchInterval: 15000,
    retry: 1,
    staleTime: 10 * 1000,
  });
};

export const useBountyWorkspaces = () => {
  return useQuery({
    queryKey: ['bounty-workspaces'],
    queryFn: apiService.getBountyWorkspaces,
    retry: 1,
    staleTime: 20 * 1000,
  });
};

export const useBountyWorkspace = (workspaceId: string | null) => {
  return useQuery({
    queryKey: ['bounty-workspace', workspaceId],
    queryFn: () => apiService.getBountyWorkspace(workspaceId as string),
    enabled: !!workspaceId,
    retry: 1,
    staleTime: 10 * 1000,
  });
};

export const useBountySkills = () => {
  return useQuery({
    queryKey: ['bounty-skills'],
    queryFn: apiService.getBountySkills,
    retry: 1,
    staleTime: 5 * 60 * 1000,
  });
};

export const useFlows = () => {
  return useQuery({
    queryKey: ['flows'],
    queryFn: apiService.getFlows,
    retry: 1,
    staleTime: 5 * 60 * 1000,
  });
};

export const useRunDetail = (runId: string | null) => {
  return useQuery({
    queryKey: ['run', runId],
    queryFn: () => apiService.getRun(runId as string),
    enabled: !!runId,
    retry: 1,
    staleTime: 5 * 1000,
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

