
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  Clock, 
  Terminal, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Eye,
  Download,
  RefreshCw
} from "lucide-react";

interface ExecutionHistory {
  id: string;
  module: string;
  script: string;
  parameters: { [key: string]: string };
  timestamp: string;
  status: "success" | "error" | "warning";
  execution_time: string;
  output?: string;
  error?: string;
}

const History = () => {
  const [selectedExecution, setSelectedExecution] = useState<ExecutionHistory | null>(null);

  const { data: history, isLoading, refetch } = useQuery<ExecutionHistory[]>({
    queryKey: ['execution-history'],
    queryFn: async (): Promise<ExecutionHistory[]> => {
      // Simulación - en producción vendría del endpoint /history
      return [
        {
          id: "20250619_143022_red_ghost_scanner",
          module: "red",
          script: "ghost_scanner",
          parameters: { target: "192.168.1.0", delay: "0.5" },
          timestamp: "2025-06-19T14:30:22.123Z",
          status: "success",
          execution_time: "0:00:15.456",
          output: "Escaneando red 192.168.1.0/24...\nHosts activos encontrados: 12\nEscaneo completado exitosamente."
        },
        {
          id: "20250619_142010_blue_ioc_matcher",
          module: "blue",
          script: "ioc_matcher",
          parameters: { file: "/var/log/auth.log" },
          timestamp: "2025-06-19T14:20:10.789Z",
          status: "warning",
          execution_time: "0:00:08.234",
          output: "Analizando archivo de logs...\n3 IOCs encontrados\n1 coincidencia sospechosa detectada",
          error: "Advertencia: 1 IOC sin resolver"
        },
        {
          id: "20250619_141505_purple_threat_emulator",
          module: "purple",
          script: "threat_emulator",
          parameters: { threat: "apt", output: "/tmp/simulation.log" },
          timestamp: "2025-06-19T14:15:05.456Z",
          status: "success",
          execution_time: "0:01:23.789",
          output: "Iniciando simulación APT...\nGenerando tráfico sospechoso...\nSimulación completada correctamente."
        },
        {
          id: "20250619_140330_red_c2_simulator",
          module: "red",
          script: "c2_simulator",
          parameters: { mode: "server", port: "8080" },
          timestamp: "2025-06-19T14:03:30.123Z",
          status: "error",
          execution_time: "0:00:02.567",
          error: "Error: Puerto 8080 ya está en uso"
        }
      ];
    }
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "success":
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case "error":
        return <XCircle className="w-4 h-4 text-red-400" />;
      case "warning":
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "success":
        return "bg-green-500/20 text-green-400 border-green-500";
      case "error":
        return "bg-red-500/20 text-red-400 border-red-500";
      case "warning":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500";
      default:
        return "bg-gray-500/20 text-gray-400 border-gray-500";
    }
  };

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

  const downloadOutput = (execution: ExecutionHistory) => {
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
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
        <div className="container mx-auto max-w-4xl">
          <div className="mb-6">
            <Button 
              variant="outline" 
              onClick={() => setSelectedExecution(null)}
              className="border-gray-600 text-gray-300 hover:bg-gray-700 mb-4"
            >
              ← Volver al Historial
            </Button>
            
            <h1 className="text-3xl font-bold text-cyan-400 mb-2">Detalles de Ejecución</h1>
            <p className="text-gray-300">ID: {selectedExecution.id}</p>
          </div>

          <div className="grid gap-6">
            {/* Información general */}
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-cyan-400 flex items-center space-x-2">
                  {getStatusIcon(selectedExecution.status)}
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
                    <Badge variant="outline" className="border-cyan-400 text-cyan-400">
                      {selectedExecution.module}
                    </Badge>
                  </div>
                  <div>
                    <span className="text-gray-400 text-sm block">Estado</span>
                    <Badge className={getStatusColor(selectedExecution.status)}>
                      {selectedExecution.status}
                    </Badge>
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
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => downloadOutput(selectedExecution)}
                      className="border-gray-600 text-gray-300"
                    >
                      <Download className="w-4 h-4 mr-2" />
                      Descargar
                    </Button>
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
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto">
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-cyan-400 mb-2">Historial de Ejecución</h1>
              <p className="text-gray-300">Registro de todos los scripts ejecutados en BOFA</p>
            </div>
            <Button
              onClick={() => refetch()}
              variant="outline"
              className="border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Actualizar
            </Button>
          </div>
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
                      {getStatusIcon(execution.status)}
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
                        <Badge className={getStatusColor(execution.status)}>
                          {execution.status}
                        </Badge>
                        <p className="text-gray-400 text-sm mt-1">
                          {execution.execution_time}
                        </p>
                      </div>
                      
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedExecution(execution);
                        }}
                        className="border-gray-600 text-gray-300"
                      >
                        <Eye className="w-4 h-4 mr-2" />
                        Ver
                      </Button>
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
    </div>
  );
};

export default History;
