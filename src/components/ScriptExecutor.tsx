
import { useState, useEffect } from "react";
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
import { ScriptConfig, ScriptParameter } from "@/types/script";
import { apiService } from "@/services/api";

interface ScriptExecutorProps {
  module: string;
  script: ScriptConfig;
  onBack: () => void;
  onExecutionComplete?: () => void;
}

export const ScriptExecutor = ({ module, script, onBack, onExecutionComplete }: ScriptExecutorProps) => {
  const [isRunning, setIsRunning] = useState(false);
  const [parameters, setParameters] = useState<{ [key: string]: string }>({});
  const [showAlert, setShowAlert] = useState(true);
  const [executionResult, setExecutionResult] = useState<any>(null);
  const [executionId, setExecutionId] = useState<string | null>(null);

  const handleParameterChange = (paramName: string, value: string) => {
    setParameters(prev => ({
      ...prev,
      [paramName]: value
    }));
  };

  // Poll execution status when running
  useEffect(() => {
    if (!isRunning || !executionId) return;
    const interval = setInterval(async () => {
      try {
        const status = await apiService.getExecutionStatus(executionId);
        if (["success", "error", "cancelled", "completed", "finished"].includes(status.status)) {
          setIsRunning(false);
          setExecutionResult({
            script: script.name,
            module,
            parameters,
            output: status.output || status.error || 'Sin salida',
            timestamp: new Date().toISOString(),
            executionTime: status.execution_time ? `${status.execution_time}s` : undefined,
            status: status.status,
          });
          setExecutionId(null);
          if (onExecutionComplete) onExecutionComplete();
          clearInterval(interval);
        }
      } catch (e) {
        // ignore polling errors
      }
    }, 1500);
    return () => clearInterval(interval);
  }, [isRunning, executionId, script.name, module, parameters, onExecutionComplete]);

  const handleExecute = async () => {
    if (script.category === "red" && showAlert) {
      const confirmed = window.confirm(
        "⚠️ Esta es una herramienta ofensiva. ¿Confirmas que tienes autorización para ejecutarla en este entorno?"
      );
      if (!confirmed) return;
    }

    try {
      setIsRunning(true);
      setExecutionResult(null);
      const { execution_id } = await apiService.startExecution({
        module,
        script: script.name,
        parameters,
      });
      setExecutionId(execution_id);
    } catch (e) {
      setIsRunning(false);
    }
  };

  const handleStop = async () => {
    if (executionId) {
      try { await apiService.stopExecution(executionId); } catch {}
    }
    setIsRunning(false);
  };

  const generateScriptOutput = (script: ScriptConfig): string => {
    // Enhanced outputs based on actual script configurations
    const outputs: Record<string, string> = {
      'supply_chain_scanner': `[INFO] BOFA Supply Chain Scanner v1.0 iniciado
[SCAN] Analizando dependencias en: ${parameters.project_path || './'}
[DEPTH] Profundidad de escaneo: ${parameters.scan_depth || 'deep'}
[NPM] Encontrados 127 paquetes NPM
[PYPI] Encontrados 43 paquetes Python
[VULN] 3 vulnerabilidades críticas detectadas:
  - lodash@4.17.20: CVE-2021-23337 (Prototype Pollution)
  - axios@0.21.0: CVE-2020-28168 (SSRF)
  - serialize-javascript@3.1.0: CVE-2020-7660 (XSS)
[SBOM] Generando Software Bill of Materials...
[SUCCESS] Análisis completado - ${parameters.output_format || 'json'} generado`,
      
      'ai_threat_hunter': `[INFO] BOFA AI Threat Hunter v2.0 iniciado
[ML] Cargando modelos de ML locales...
[MITRE] Integrando framework MITRE ATT&CK...
[ANALYSIS] Procesando: ${parameters.log_file || 'security.log'}
[THRESHOLD] Umbral de anomalía: ${parameters.anomaly_threshold || '0.7'}
[DETECT] ¡AMENAZA DETECTADA! - Técnica T1055 (Process Injection)
[DETECT] ¡AMENAZA DETECTADA! - Técnica T1003 (OS Credential Dumping)
[ANOMALY] Comportamiento anómalo a las 03:42:17 UTC
[SCORE] Puntuación de riesgo: 8.7/10 (CRÍTICO)
[AI] Confianza del modelo: 94.3%
[SUCCESS] Análisis IA completado - 3 amenazas de alta severidad`,
      
      'quantum_crypto_analyzer': `[INFO] BOFA Quantum-Safe Crypto Analyzer v1.0
[QUANTUM] Evaluando resistencia post-cuántica...
[ANALYSIS] Tipo: ${parameters.analysis_type || 'comprehensive'}
[RSA] RSA-2048 detectado - VULNERABLE post-2030
[ECDSA] ECDSA P-256 detectado - VULNERABLE post-2025
[AES] AES-256 detectado - SEGURO post-cuántico
[RECOMMENDATIONS] Migrar a:
  - Kyber-512 para intercambio de claves
  - Dilithium-2 para firmas digitales
  - SPHINCS+ como respaldo
[SCORE] Puntuación Quantum-Safe: 23/100 (CRÍTICO)
[SUCCESS] Plan de migración generado`,
      
      'cloud_native_attack_simulator': `[INFO] BOFA Cloud Native Attack Simulator v1.0
[TARGET] Tipo: ${parameters.target_type || 'kubernetes'}
[SCENARIO] Ejecutando: ${parameters.attack_scenarios || 'container_escape'}
[INTENSITY] Nivel: ${parameters.intensity_level || 'medium'}
[K8S] Conectando a cluster Kubernetes...
[EXPLOIT] Intentando escape de contenedor...
[SUCCESS] ¡Container escape exitoso!
[PRIV-ESC] Escalando privilegios...
[LATERAL] Movimiento lateral detectado
[ALERT] ¡Simulación completada! Vulnerabilidades encontradas:
  - Privileged container sin AppArmor
  - ServiceAccount con permisos excesivos
  - Network policies faltantes
[REMEDIATION] Generando recomendaciones...`,
      
      'iot_security_mapper': `[INFO] BOFA IoT/OT Security Mapper v1.0
[SHODAN] Conectando a Shodan API...
[QUERY] Ejecutando: ${parameters.search_query || 'port:502,1883,47808,20000'}
[PROTOCOLS] Buscando: ${parameters.target_protocols || 'modbus,mqtt,bacnet'}
[SCAN] Encontrados 847 dispositivos IoT/OT expuestos:
  - 234 dispositivos Modbus (puerto 502)
  - 156 brokers MQTT (puerto 1883)
  - 89 dispositivos BACnet (puerto 47808)
  - 368 otros dispositivos industriales
[GEOLOC] Distribución geográfica:
  - Estados Unidos: 312 dispositivos
  - Alemania: 178 dispositivos
  - China: 145 dispositivos
[VULN] 23 dispositivos con vulnerabilidades críticas
[SUCCESS] Mapeo IoT/OT completado`,
      
      'malware_analyzer': `[INFO] BOFA Malware Analyzer v1.0
[STATIC] Iniciando análisis estático...
[FILE] Analizando: ${parameters.file_path || 'suspicious.exe'}
[DEPTH] Profundidad: ${parameters.analysis_depth || 'standard'}
[HASH] MD5: 5d41402abc4b2a76b9719d911017c592
[HASH] SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
[HASH] SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
[PATTERNS] Detectados 7 patrones sospechosos:
  - Conexiones de red cifradas
  - Modificación de registro
  - Evasión de detección
  - Técnicas de ofuscación
[NETWORK] URLs maliciosas detectadas:
  - http://malicious-c2.com/gate.php
  - https://evil-domain.net/upload
[RISK] Nivel de riesgo: ALTO (8.5/10)
[SUCCESS] Análisis estático completado`,
      
      'social_engineer_toolkit': `[INFO] BOFA Social Engineering Toolkit v1.0 (EDUCATIVO)
[TARGET] Perfil: ${parameters.target_name || 'Usuario Ejemplo'}
[ROLE] Rol: ${parameters.target_role || 'employee'}
[SCENARIO] Tipo: ${parameters.scenario_type || 'it_support'}
[PSYCHOLOGY] Analizando vulnerabilidades psicológicas...
[PRETEXT] Generando escenarios de pretexto:
  - "Soporte técnico urgente - verificación de credenciales"
  - "Actualización de seguridad - confirmar acceso"
  - "Auditoría interna - validar información"
[PHISHING] Ejemplos de emails generados (SOLO EDUCATIVO):
  - Subject: "Acción requerida: Verificar cuenta de empresa"
  - Subject: "Alerta de seguridad: Actividad sospechosa detectada"
[DEFENSE] Recomendaciones defensivas:
  - Verificación telefónica independiente
  - Políticas de verificación de identidad
  - Entrenamiento de concienciación
[SUCCESS] Análisis educativo completado - Material de entrenamiento generado`,
      
      'zero_trust_validator': `[INFO] BOFA Zero Trust Validator v1.0
[ENVIRONMENT] Validando: ${parameters.environment || 'production'}
[SCOPE] Alcance: ${parameters.scope || 'all'}
[IDENTITY] Verificando verificación de identidad...
  ✓ Multi-factor authentication habilitado
  ✗ Conditional access incompleto
[DEVICE] Evaluando confianza de dispositivos...
  ✓ Device compliance policies activas
  ✓ Certificate-based authentication
[NETWORK] Analizando micro-segmentación...
  ✗ Network segmentation insuficiente
  ✓ Traffic encryption habilitado
[PRIVILEGE] Validando least privilege...
  ✗ 23% usuarios con privilegios excesivos
  ✓ Just-in-time access implementado
[SCORE] Zero Trust Score: 74/100
[RECOMMENDATIONS] 8 mejoras críticas identificadas
[SUCCESS] Validación Zero Trust completada`
    };
    
    return outputs[script.name] || `[INFO] Ejecutando ${script.display_name || script.name}...
[PARAMS] Parámetros: ${JSON.stringify(parameters, null, 2)}
[PROCESSING] Procesando solicitud...
[SUCCESS] Script ejecutado exitosamente
[OUTPUT] Resultados disponibles en formato ${parameters.output_format || 'texto'}
[INFO] Ejecución completada sin errores`;
  };

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
            <h1 className="text-3xl font-bold text-cyan-400">{script.display_name || script.name}</h1>
            {script.last_updated === "2025-01-20" && (
              <span className="px-3 py-1 bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-sm rounded-full font-bold animate-pulse">
                ✨ NUEVO 2025
              </span>
            )}
            {script.risk_level && (
              <span className={`px-2 py-1 rounded text-xs font-bold ${
                script.risk_level === 'HIGH' ? 'bg-red-600 text-white' :
                script.risk_level === 'MEDIUM' ? 'bg-yellow-600 text-black' : 
                'bg-green-600 text-white'
              }`}>
                RIESGO: {script.risk_level}
              </span>
            )}
          </div>
          <p className="text-gray-300 mb-2">{script.description}</p>
          {script.tags && script.tags.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {script.tags.map((tag, index) => (
                <span key={index} className="px-2 py-1 bg-gray-700 text-cyan-400 text-xs rounded">
                  {tag}
                </span>
              ))}
            </div>
          )}
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
                {script.educational_value && (
                  <div className="pt-2 border-t border-gray-600">
                    <span className="text-gray-400">Valor Educativo:</span>
                    <div className="ml-2 flex">
                      {[...Array(5)].map((_, i) => (
                        <span key={i} className={i < script.educational_value! ? 'text-yellow-400' : 'text-gray-600'}>
                          ⭐
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Alertas */}
            {showAlert && (
              <ScriptAlert script={script} />
            )}

            {/* Parámetros */}
            {script.parameters && Object.keys(script.parameters).length > 0 && (
              <Card className="bg-gray-800/50 border-gray-700">
                <CardHeader>
                  <CardTitle className="text-cyan-400">Parámetros</CardTitle>
                  <CardDescription>Configura los parámetros del script</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {Object.entries(script.parameters).map(([paramName, paramConfig]: [string, ScriptParameter]) => (
                    <div key={paramName}>
                      <Label htmlFor={paramName} className="text-gray-300">
                        {paramName.replace('_', ' ').toUpperCase()}
                        {paramConfig.required && <span className="text-red-400 ml-1">*</span>}
                      </Label>
                      {paramConfig.type === 'select' ? (
                        <Select
                          value={parameters[paramName] || String(paramConfig.default) || ''}
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
                      ) : paramConfig.type === 'boolean' ? (
                        <Select
                          value={parameters[paramName] || String(paramConfig.default) || 'false'}
                          onValueChange={(value) => handleParameterChange(paramName, value)}
                        >
                          <SelectTrigger className="mt-1 bg-gray-700 border-gray-600 text-white">
                            <SelectValue placeholder={paramConfig.description} />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="true">SÍ</SelectItem>
                            <SelectItem value="false">NO</SelectItem>
                          </SelectContent>
                        </Select>
                      ) : (
                        <Input
                          id={paramName}
                          type={paramConfig.type === "number" ? "number" : "text"}
                          placeholder={paramConfig.description}
                          value={parameters[paramName] || String(paramConfig.default || "")}
                          onChange={(e) => handleParameterChange(paramName, e.target.value)}
                          className="mt-1 bg-gray-700 border-gray-600 text-white"
                          min={paramConfig.min}
                          max={paramConfig.max}
                        />
                      )}
                      <p className="text-xs text-gray-400 mt-1">
                        {paramConfig.description}
                        {paramConfig.example && ` (ej: ${paramConfig.example})`}
                      </p>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Características */}
            {script.features && script.features.length > 0 && (
              <Card className="bg-gray-800/50 border-gray-700">
                <CardHeader>
                  <CardTitle className="text-cyan-400">Características</CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {script.features.map((feature, index) => (
                      <li key={index} className="text-sm text-gray-300 flex items-start">
                        <span className="text-cyan-400 mr-2">•</span>
                        {feature}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}

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
          <ScriptExecutionConsole 
            script={script} 
            isRunning={isRunning}
            executionId={executionId}
          />
          </div>
        </div>
      </div>
    </div>
  );
};
