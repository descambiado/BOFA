import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ArrowLeft, Play, Square, Terminal, Clock } from "lucide-react";

interface Script {
  name: string;
  description: string;
  category: string;
  author: string;
  version: string;
  last_updated: string;
}

interface ScriptExecutorProps {
  module: string;
  script: Script;
  onBack: () => void;
  onExecutionComplete?: () => void;
}

export const ScriptExecutor = ({ module, script, onBack, onExecutionComplete }: ScriptExecutorProps) => {
  const [isExecuting, setIsExecuting] = useState(false);
  const [output, setOutput] = useState<string[]>([]);
  const [parameters, setParameters] = useState<{ [key: string]: string }>({});
  const [executionHistory, setExecutionHistory] = useState<Array<{
    timestamp: string;
    script: string;
    parameters: any;
    success: boolean;
  }>>([]);
  
  const outputRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  const getScriptParameters = (scriptName: string) => {
    const paramMap: { [key: string]: Array<{ name: string; label: string; type: string; placeholder: string }> } = {
      "web_discover.py": [
        { name: "domain", label: "Dominio objetivo", type: "text", placeholder: "example.com" },
        { name: "timeout", label: "Timeout (segundos)", type: "number", placeholder: "5" },
        { name: "threads", label: "Número de threads", type: "number", placeholder: "50" }
      ],
      "port_slayer.sh": [
        { name: "target", label: "Target (IP/dominio)", type: "text", placeholder: "192.168.1.1" },
        { name: "mode", label: "Modo", type: "select", placeholder: "f=fast, s=stealth, a=all" }
      ],
      "social_profile_mapper.py": [
        { name: "username", label: "Nombre de usuario", type: "text", placeholder: "johndoe" },
        { name: "variations", label: "Buscar variaciones", type: "checkbox", placeholder: "" }
      ],
      "reverse_shell_generator.py": [
        { name: "ip", label: "IP del atacante", type: "text", placeholder: "192.168.1.100" },
        { name: "port", label: "Puerto", type: "number", placeholder: "4444" }
      ],
      "log_guardian.py": [
        { name: "log_file", label: "Archivo de log", type: "text", placeholder: "/var/log/auth.log" }
      ],
      "learn_sql_injection.py": [],
      "xss_trainer.py": [],
      "malware_basics.py": [],
      "network_layers_tutorial.py": []
    };
    
    return paramMap[scriptName] || [];
  };

  const executeScript = async () => {
    setIsExecuting(true);
    setOutput([]);
    
    try {
      const response = await fetch(`http://localhost:8000/scripts/${module}/${script.name}/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ parameters })
      });

      if (!response.ok) {
        throw new Error(`Error: ${response.status}`);
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error('No se pudo leer la respuesta');

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const text = new TextDecoder().decode(value);
        const lines = text.split('\n').filter(line => line.trim());
        
        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            if (data.output) {
              setOutput(prev => [...prev, data.output]);
            }
            if (data.error) {
              setOutput(prev => [...prev, `ERROR: ${data.error}`]);
            }
            if (data.completed) {
              setOutput(prev => [...prev, "🎉 Ejecución completada"]);
              
              // Guardar en historial
              const historyEntry = {
                timestamp: new Date().toISOString(),
                script: script.name,
                parameters,
                success: true
              };
              setExecutionHistory(prev => [historyEntry, ...prev]);
              
              // Llamar callback de completado si existe
              if (onExecutionComplete) {
                onExecutionComplete();
              }
            }
          } catch (e) {
            setOutput(prev => [...prev, text]);
          }
        }
      }
    } catch (error) {
      setOutput(prev => [...prev, `❌ Error: ${error instanceof Error ? error.message : 'Error desconocido'}`]);
      
      // Guardar error en historial
      const historyEntry = {
        timestamp: new Date().toISOString(),
        script: script.name,
        parameters,
        success: false
      };
      setExecutionHistory(prev => [historyEntry, ...prev]);
    } finally {
      setIsExecuting(false);
    }
  };

  const stopExecution = () => {
    setIsExecuting(false);
    setOutput(prev => [...prev, "⚠️ Ejecución detenida por el usuario"]);
  };

  const scriptParams = getScriptParameters(script.name);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto">
        <div className="mb-6">
          <Button 
            variant="outline" 
            onClick={onBack}
            className="border-gray-600 text-gray-300 hover:bg-gray-700"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Volver
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Script Info & Parameters */}
          <div className="lg:col-span-1 space-y-6">
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-cyan-400">{script.name}</CardTitle>
                <CardDescription className="text-gray-300">{script.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm text-gray-400">
                  <p><span className="text-cyan-400">Categoría:</span> {script.category}</p>
                  <p><span className="text-cyan-400">Autor:</span> {script.author}</p>
                  <p><span className="text-cyan-400">Versión:</span> {script.version}</p>
                  <p><span className="text-cyan-400">Actualizado:</span> {script.last_updated}</p>
                </div>
              </CardContent>
            </Card>

            {scriptParams.length > 0 && (
              <Card className="bg-gray-800/50 border-gray-700">
                <CardHeader>
                  <CardTitle className="text-cyan-400">Parámetros</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {scriptParams.map((param) => (
                      <div key={param.name}>
                        <Label htmlFor={param.name} className="text-gray-300">{param.label}</Label>
                        {param.type === "checkbox" ? (
                          <div className="flex items-center space-x-2 mt-1">
                            <input
                              type="checkbox"
                              id={param.name}
                              checked={parameters[param.name] === "true"}
                              onChange={(e) => setParameters(prev => ({
                                ...prev,
                                [param.name]: e.target.checked.toString()
                              }))}
                              className="w-4 h-4"
                            />
                            <span className="text-sm text-gray-400">{param.placeholder}</span>
                          </div>
                        ) : (
                          <Input
                            id={param.name}
                            type={param.type}
                            placeholder={param.placeholder}
                            value={parameters[param.name] || ""}
                            onChange={(e) => setParameters(prev => ({
                              ...prev,
                              [param.name]: e.target.value
                            }))}
                            className="bg-gray-900 border-gray-600 text-white mt-1"
                          />
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            <div className="space-y-3">
              <Button 
                onClick={executeScript}
                disabled={isExecuting}
                className="w-full bg-green-600 hover:bg-green-700 disabled:opacity-50"
              >
                {isExecuting ? (
                  <>
                    <Square className="w-4 h-4 mr-2" />
                    Ejecutando...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" />
                    Ejecutar Script
                  </>
                )}
              </Button>
              
              {isExecuting && (
                <Button 
                  onClick={stopExecution}
                  variant="destructive"
                  className="w-full"
                >
                  <Square className="w-4 h-4 mr-2" />
                  Detener
                </Button>
              )}
            </div>
          </div>

          {/* Terminal Output */}
          <div className="lg:col-span-2">
            <Card className="bg-gray-800/50 border-gray-700 h-[600px] flex flex-col">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-cyan-400 flex items-center">
                    <Terminal className="w-5 h-5 mr-2" />
                    Terminal de Salida
                  </CardTitle>
                  {isExecuting && (
                    <div className="flex items-center text-yellow-400">
                      <Clock className="w-4 h-4 mr-1 animate-spin" />
                      Ejecutando...
                    </div>
                  )}
                </div>
              </CardHeader>
              <CardContent className="flex-1 overflow-hidden">
                <div 
                  ref={outputRef}
                  className="h-full bg-black rounded p-4 font-mono text-sm overflow-y-auto space-y-1"
                >
                  {output.length === 0 ? (
                    <div className="text-gray-400">
                      Ejecuta el script para ver la salida...
                    </div>
                  ) : (
                    output.map((line, index) => (
                      <div key={index} className="text-green-400">
                        <span className="text-gray-500">[{new Date().toLocaleTimeString()}]</span> {line}
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Execution History */}
        {executionHistory.length > 0 && (
          <Card className="bg-gray-800/50 border-gray-700 mt-6">
            <CardHeader>
              <CardTitle className="text-cyan-400">Historial de Ejecuciones</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {executionHistory.slice(0, 5).map((entry, index) => (
                  <div key={index} className="flex items-center justify-between p-2 bg-gray-900 rounded">
                    <div className="flex items-center space-x-3">
                      <div className={`w-2 h-2 rounded-full ${entry.success ? 'bg-green-400' : 'bg-red-400'}`}></div>
                      <span className="text-sm text-gray-300">{entry.script}</span>
                      <span className="text-xs text-gray-500">
                        {new Date(entry.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <span className={`text-xs ${entry.success ? 'text-green-400' : 'text-red-400'}`}>
                      {entry.success ? '✅ Éxito' : '❌ Error'}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};
