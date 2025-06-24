
import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ArrowLeft, Play, Square } from "lucide-react";
import { ScriptAlert } from "@/components/ScriptAlert";
import { ScriptExecutionConsole } from "@/components/ScriptExecutionConsole";
import { ReportExporter } from "@/components/ReportExporter";
import { ActionButton } from "@/components/UI/ActionButton";

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

interface ScriptExecutorProps {
  module: string;
  script: Script;
  onBack: () => void;
  onExecutionComplete?: () => void;
}

export const ScriptExecutor = ({ module, script, onBack, onExecutionComplete }: ScriptExecutorProps) => {
  const [isRunning, setIsRunning] = useState(false);
  const [parameters, setParameters] = useState<{ [key: string]: string }>({});
  const [showAlert, setShowAlert] = useState(true);
  const [executionResult, setExecutionResult] = useState<any>(null);

  const handleParameterChange = (paramName: string, value: string) => {
    setParameters(prev => ({
      ...prev,
      [paramName]: value
    }));
  };

  const handleExecute = () => {
    if (script.category === "red" && showAlert) {
      const confirmed = window.confirm(
        "⚠️ Esta es una herramienta ofensiva. ¿Confirmas que tienes autorización para ejecutarla en este entorno?"
      );
      if (!confirmed) return;
    }
    
    setIsRunning(true);
    
    // Simular ejecución y guardar resultado
    setTimeout(() => {
      const result = {
        script: script.name,
        module: module,
        parameters: parameters,
        output: generateScriptOutput(script),
        timestamp: new Date().toISOString(),
        executionTime: (Math.random() * 5 + 1).toFixed(1) + "s",
        status: "success"
      };
      
      setExecutionResult(result);
      setIsRunning(false);
      
      if (onExecutionComplete) {
        onExecutionComplete();
      }
    }, 3000);
  };

  const handleStop = () => {
    setIsRunning(false);
  };

  const generateScriptOutput = (script: Script): string => {
    const outputs = {
      'supply_chain_scanner': `[INFO] Iniciando análisis de cadena de suministro...
[SCAN] Analizando dependencias NPM...
[FOUND] 15 paquetes con vulnerabilidades conocidas
[ANALYSIS] Verificando integridad de packages...
[ALERT] Paquete 'lodash@4.17.20' - CVE-2021-23337
[SUCCESS] Análisis completado - 3 riesgos críticos detectados`,
      
      'ai_threat_hunter': `[AI] Iniciando análisis con ML local...
[ML] Cargando modelo de detección de amenazas...
[ANALYSIS] Procesando patrones MITRE ATT&CK...
[DETECTION] Anomalía temporal detectada - 23:45:12
[AI] Comportamiento sospechoso identificado: Lateral Movement
[THREAT] Nivel de riesgo: ALTO (0.87/1.0)
[SUCCESS] Análisis IA completado`,
      
      'quantum_crypto_analyzer': `[QUANTUM] Evaluando resistencia criptográfica...
[RSA] Clave RSA-2048 - Vulnerable post-2030
[ECDSA] Curva P-256 - Requiere migración
[RECOMMENDATION] Migrar a algoritmos post-cuánticos
[PLAN] Generando estrategia de migración...
[SUCCESS] Evaluación cuántica completada`,
      
      'deepfake_detection_engine': `[DEEPFAKE] Analizando contenido multimedia...
[FACIAL] Detectando inconsistencias faciales...
[TEMPORAL] Analizando coherencia temporal...
[COMPRESSION] Verificando artefactos de compresión...
[RESULT] Probabilidad de deepfake: 0.23 (BAJO)
[SUCCESS] Análisis de deepfake completado`,
      
      'zero_trust_validator': `[ZERO-TRUST] Validando implementación...
[MICROSEG] Verificando micro-segmentación...
[IDENTITY] Validando verificación de identidad...
[PRIVILEGE] Analizando least privilege...
[SCORE] Zero Trust Score: 78/100
[RECOMMENDATIONS] 5 mejoras identificadas
[SUCCESS] Validación Zero Trust completada`
    };
    
    return outputs[script.name as keyof typeof outputs] || `[INFO] Ejecutando ${script.name}...
[SUCCESS] Script ejecutado exitosamente
[INFO] Proceso completado`;
  };

  // Parámetros simulados basados en el script
  const getScriptParameters = () => {
    const scriptParams: { [key: string]: any } = {
      'supply_chain_scanner': {
        'package_manager': { type: 'select', options: ['npm', 'pip', 'maven'], description: 'Gestor de paquetes', required: true },
        'depth': { type: 'number', description: 'Profundidad de análisis', required: false, default: '3' }
      },
      'ai_threat_hunter': {
        'log_file': { type: 'string', description: 'Archivo de logs a analizar', required: true },
        'model': { type: 'select', options: ['local', 'cloud'], description: 'Modelo de IA', required: false, default: 'local' }
      },
      'quantum_crypto_analyzer': {
        'target': { type: 'string', description: 'Sistema objetivo', required: true },
        'algorithm': { type: 'select', options: ['rsa', 'ecdsa', 'all'], description: 'Algoritmo a evaluar', required: false, default: 'all' }
      },
      'deepfake_detection_engine': {
        'media_file': { type: 'string', description: 'Archivo multimedia', required: true },
        'threshold': { type: 'number', description: 'Umbral de detección', required: false, default: '0.5' }
      },
      'zero_trust_validator': {
        'environment': { type: 'select', options: ['production', 'staging', 'development'], description: 'Entorno', required: true },
        'scope': { type: 'select', options: ['network', 'identity', 'device', 'all'], description: 'Alcance', required: false, default: 'all' }
      }
    };

    return scriptParams[script.name] || {
      'target': { type: 'string', description: 'Objetivo del script', required: true },
      'output': { type: 'string', description: 'Archivo de salida', required: false }
    };
  };

  const scriptParams = getScriptParameters();

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto max-w-6xl">
        {/* Header */}
        <div className="mb-6">
          <ActionButton
            icon={<ArrowLeft className="w-4 h-4" />}
            title="Volver"
            description="Volver a Scripts"
            onClick={onBack}
            className="mb-4 w-auto"
          />
          
          <div className="flex items-center space-x-4 mb-4">
            <h1 className="text-3xl font-bold text-cyan-400">{script.name}</h1>
            {script.last_updated === "2025-01-20" && (
              <span className="px-3 py-1 bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-sm rounded-full font-bold animate-pulse">
                ✨ NUEVO 2025
              </span>
            )}
          </div>
          <p className="text-gray-300">{script.description}</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Panel de configuración */}
          <div className="space-y-6">
            {/* Información del script */}
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-cyan-400">Información del Script</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-400">Autor:</span>
                    <span className="ml-2 text-white">{script.author}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Versión:</span>
                    <span className="ml-2 text-white">{script.version}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Categoría:</span>
                    <span className="ml-2 text-white capitalize">{script.category}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Actualizado:</span>
                    <span className="ml-2 text-white">{script.last_updated}</span>
                  </div>
                </div>
                {script.impact_level && (
                  <div className="pt-2 border-t border-gray-600">
                    <span className="text-gray-400">Nivel de Impacto:</span>
                    <span className={`ml-2 px-2 py-1 rounded text-xs ${
                      script.impact_level === 'HIGH' ? 'bg-red-600' :
                      script.impact_level === 'MEDIUM' ? 'bg-yellow-600' : 'bg-green-600'
                    }`}>
                      {script.impact_level}
                    </span>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Alertas */}
            {showAlert && (
              <ScriptAlert script={script} />
            )}

            {/* Parámetros */}
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-cyan-400">Parámetros</CardTitle>
                <CardDescription>Configura los parámetros del script</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {Object.entries(scriptParams).map(([paramName, paramConfig]) => (
                  <div key={paramName}>
                    <Label htmlFor={paramName} className="text-gray-300">
                      {paramName.replace('_', ' ').toUpperCase()}
                      {paramConfig.required && <span className="text-red-400 ml-1">*</span>}
                    </Label>
                    {paramConfig.type === 'select' ? (
                      <Select
                        value={parameters[paramName] || paramConfig.default || ''}
                        onValueChange={(value) => handleParameterChange(paramName, value)}
                      >
                        <SelectTrigger className="mt-1 bg-gray-700 border-gray-600 text-white">
                          <SelectValue placeholder={paramConfig.description} />
                        </SelectTrigger>
                        <SelectContent>
                          {paramConfig.options?.map((option: string) => (
                            <SelectItem key={option} value={option}>
                              {option.toUpperCase()}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : (
                      <Input
                        id={paramName}
                        type={paramConfig.type === "number" ? "number" : "text"}
                        placeholder={paramConfig.description}
                        value={parameters[paramName] || paramConfig.default || ""}
                        onChange={(e) => handleParameterChange(paramName, e.target.value)}
                        className="mt-1 bg-gray-700 border-gray-600 text-white"
                      />
                    )}
                    <p className="text-xs text-gray-400 mt-1">{paramConfig.description}</p>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Controles de ejecución */}
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-cyan-400">Ejecución</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex space-x-3">
                  {!isRunning ? (
                    <Button 
                      onClick={handleExecute}
                      className="bg-green-600 hover:bg-green-700 flex-1"
                    >
                      <Play className="w-4 h-4 mr-2" />
                      Ejecutar Script
                    </Button>
                  ) : (
                    <Button 
                      onClick={handleStop}
                      variant="destructive"
                      className="flex-1"
                    >
                      <Square className="w-4 h-4 mr-2" />
                      Detener
                    </Button>
                  )}
                </div>
                
                {/* Exportador de reportes */}
                {executionResult && (
                  <div className="mt-4 pt-4 border-t border-gray-600">
                    <div className="flex justify-center">
                      <ReportExporter executionData={executionResult} />
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Panel de consola */}
          <div>
            <ScriptExecutionConsole script={script} isRunning={isRunning} />
          </div>
        </div>
      </div>
    </div>
  );
};
