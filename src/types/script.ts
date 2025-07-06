
export interface ScriptParameter {
  type: 'string' | 'number' | 'boolean' | 'select' | 'file' | 'directory' | 'multiselect' | 'choice';
  description: string;
  required: boolean;
  default?: string | number | boolean;
  options?: string[];
  choices?: string[];
  min?: number;
  max?: number;
  accepted_types?: string[];
  example?: string | string[];
}

export interface ScriptConfig {
  name: string;
  display_name?: string;
  description: string;
  category: string;
  subcategory?: string;
  author: string;
  version: string;
  last_updated: string;
  risk_level?: 'LOW' | 'MEDIUM' | 'HIGH';
  impact_level?: 'LOW' | 'MEDIUM' | 'HIGH';
  educational_value?: number;
  tags?: string[];
  parameters?: Record<string, ScriptParameter>;
  requirements?: string[];
  features?: string[];
  usage_examples?: string[];
  learning_objectives?: string[];
  warnings?: string[];
  mitre_attack?: {
    tactic: string;
    technique: string;
  };
  execution?: {
    timeout: number;
    memory_limit: string;
    cpu_limit: string;
  };
  output?: {
    format: string;
    fields: string[];
  };
  dashboard?: {
    enabled: boolean;
    widgets: Array<{
      type: string;
      title: string;
      field: string;
      chart_type?: string;
      min?: number;
      max?: number;
    }>;
  };
}

export interface ExecutionHistory {
  id: string;
  script_name: string;
  module: string;
  parameters: Record<string, any>;
  timestamp: string;
  status: 'success' | 'error' | 'warning' | 'running';
  execution_time?: string;
  output?: string;
  error?: string;
}
