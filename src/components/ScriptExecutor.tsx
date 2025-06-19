import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ArrowLeft, Play, Square } from "lucide-react";
import { ScriptAlert } from "@/components/ScriptAlert";
import { ScriptExecutionConsole } from "@/components/ScriptExecutionConsole";

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
    
    // Simular ejecución por 3 segundos
    setTimeout(() => {
      setIsRunning(false);
      // Call onExecutionComplete if provided
      if (onExecutionComplete) {
        onExecutionComplete();
      }
    }, 3000);
  };

  const handleStop = () => {
    setIsRunning(false);
  };

  // Parámetros simulados basados en el script
  const getScriptParameters = () => {
    const commonParams = {
      "target": { type: "string", description: "Objetivo del script", required: true },
      "output": { type: "string", description: "Archivo de salida", required: false }
    };

    if (script.category === "red") {
      return {
        ...commonParams,
        "delay": { type: "number", description: "Delay entre operaciones", required: false }
      };
    }

    if (script.category === "blue") {
      return {
        "file": { type: "string", description: "Archivo de log a analizar", required: true },
        "format": { type: "select", options: ["json", "csv", "txt"], description: "Formato de salida", required: false }
      };
    }

    return commonParams;
  };

  const scriptParams = getScriptParameters();

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto max-w-4xl">
        {/* Header */}
        <div className="mb-6">
          <Button 
            variant="outline" 
            onClick={onBack}
            className="border-gray-600 text-gray-300 hover:bg-gray-700 mb-4"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Volver
          </Button>
          
          <h1 className="text-3xl font-bold text-cyan-400 mb-2">{script.name}</h1>
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
                    <span className="ml-2 text-white">{script.category}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Actualizado:</span>
                    <span className="ml-2 text-white">{script.last_updated}</span>
                  </div>
                </div>
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
                      {paramName}
                      {paramConfig.required && <span className="text-red-400 ml-1">*</span>}
                    </Label>
                    <Input
                      id={paramName}
                      type={paramConfig.type === "number" ? "number" : "text"}
                      placeholder={paramConfig.description}
                      value={parameters[paramName] || ""}
                      onChange={(e) => handleParameterChange(paramName, e.target.value)}
                      className="mt-1 bg-gray-700 border-gray-600 text-white"
                    />
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
