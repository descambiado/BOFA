
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/UI/StatusBadge";
import { ActionButton } from "@/components/UI/ActionButton";
import { useExecutionHistory } from "@/services/api";
import { 
  Clock, 
  Terminal, 
  Eye,
  Download,
  RefreshCw,
  XCircle,
  ArrowLeft
} from "lucide-react";

const History = () => {
  const [selectedExecution, setSelectedExecution] = useState<any>(null);
  const { data: history, isLoading, refetch } = useExecutionHistory();

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('es-ES', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const downloadOutput = (execution: any) => {
    const content = `BOFA - Historial de Ejecución
ID: ${execution.id}
Script: ${execution.script}
Módulo: ${execution.module}
Timestamp: ${formatTimestamp(execution.timestamp)}
Estado: ${execution.status}
Tiempo: ${execution.execution_time}
Parámetros: ${JSON.stringify(execution.parameters, null, 2)}

=== SALIDA ===
${execution.output || 'Sin salida'}

=== ERRORES ===
${execution.error || 'Sin errores'}`;

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bofa-execution-${execution.id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (selectedExecution) {
    return (
      <div className="container mx-auto px-6 py-8">
        <div className="mb-6">
          <ActionButton
            icon={<ArrowLeft className="w-4 h-4" />}
            title="Volver"
            description="Volver al Historial"
            onClick={() => setSelectedExecution(null)}
          />
          
          <h1 className="text-3xl font-bold text-cyan-400 mb-2 mt-4">Detalles de Ejecución</h1>
          <p className="text-gray-300">ID: {selectedExecution.id}</p>
        </div>

        <div className="grid gap-6">
          {/* Información general */}
          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="text-cyan-400 flex items-center space-x-2">
                <StatusBadge status={selectedExecution.status} />
                <span>Información General</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <span className="text-gray-400 text-sm block">Script</span>
                  <span className="text-white font-mono">{selectedExecution.script}</span>
                </div>
                <div>
                  <span className="text-gray-400 text-sm block">Módulo</span>
                  <StatusBadge status={selectedExecution.module} text={selectedExecution.module} />
                </div>
                <div>
                  <span className="text-gray-400 text-sm block">Estado</span>
                  <StatusBadge status={selectedExecution.status} />
                </div>
                <div>
                  <span className="text-gray-400 text-sm block">Duración</span>
                  <span className="text-white">{selectedExecution.execution_time}</span>
                </div>
              </div>
              
              <div>
                <span className="text-gray-400 text-sm block mb-2">Fecha y Hora</span>
                <span className="text-white">{formatTimestamp(selectedExecution.timestamp)}</span>
              </div>

              {Object.keys(selectedExecution.parameters).length > 0 && (
                <div>
                  <span className="text-gray-400 text-sm block mb-2">Parámetros</span>
                  <div className="bg-gray-900 p-3 rounded-lg font-mono text-sm">
                    <pre className="text-gray-300">
                      {JSON.stringify(selectedExecution.parameters, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Salida del script */}
          {selectedExecution.output && (
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-cyan-400 flex items-center space-x-2">
                    <Terminal className="w-5 h-5" />
                    <span>Salida del Script</span>
                  </CardTitle>
                  <ActionButton
                    icon={<Download className="w-4 h-4" />}
                    title="Descargar"
                    description="Descargar salida"
                    onClick={() => downloadOutput(selectedExecution)}
                  />
                </div>
              </CardHeader>
              <CardContent>
                <div className="bg-black p-4 rounded-lg font-mono text-sm max-h-64 overflow-y-auto">
                  <pre className="text-green-400 whitespace-pre-wrap">
                    {selectedExecution.output}
                  </pre>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Errores */}
          {selectedExecution.error && (
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-red-400 flex items-center space-x-2">
                  <XCircle className="w-5 h-5" />
                  <span>Errores</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-black p-4 rounded-lg font-mono text-sm">
                  <pre className="text-red-400 whitespace-pre-wrap">
                    {selectedExecution.error}
                  </pre>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-cyan-400 mb-2">Historial de Ejecución</h1>
          <p className="text-gray-300">Registro de todos los scripts ejecutados en BOFA</p>
        </div>
        <ActionButton
          icon={<RefreshCw className="w-4 h-4" />}
          title="Actualizar"
          description="Refrescar historial"
          onClick={() => refetch()}
        />
      </div>

      {isLoading ? (
        <div className="text-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto"></div>
          <p className="text-gray-400 mt-4">Cargando historial...</p>
        </div>
      ) : !history || history.length === 0 ? (
        <Card className="bg-gray-800/50 border-gray-700">
          <CardContent className="text-center py-12">
            <Clock className="w-12 h-12 text-gray-500 mx-auto mb-4" />
            <h3 className="text-xl text-gray-400 mb-2">Sin ejecuciones registradas</h3>
            <p className="text-gray-500">Ejecuta algunos scripts para ver el historial aquí</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {history.map((execution) => (
            <Card 
              key={execution.id} 
              className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all cursor-pointer"
              onClick={() => setSelectedExecution(execution)}
            >
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <StatusBadge status={execution.status} />
                    <div>
                      <h3 className="text-lg font-semibold text-white">
                        {execution.script}
                      </h3>
                      <p className="text-gray-400 text-sm">
                        {formatTimestamp(execution.timestamp)}
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <p className="text-gray-400 text-sm">
                        {execution.execution_time}
                      </p>
                    </div>
                    
                    <ActionButton
                      icon={<Eye className="w-4 h-4" />}
                      title="Ver"
                      description="Ver detalles"
                      onClick={() => setSelectedExecution(execution)}
                    />
                  </div>
                </div>
                
                <div className="mt-4 flex items-center space-x-4 text-sm text-gray-400">
                  <span>Módulo: <span className="text-cyan-400">{execution.module}</span></span>
                  {Object.keys(execution.parameters).length > 0 && (
                    <span>
                      Parámetros: {Object.keys(execution.parameters).length} configurados
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

export default History;
