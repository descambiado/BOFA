
import { useState, useRef, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Download, Terminal } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface LogEntry {
  timestamp: string;
  level: "INFO" | "WARN" | "ERROR" | "SUCCESS";
  message: string;
}

interface ScriptExecutionConsoleProps {
  script: {
    name: string;
  };
  isRunning: boolean;
}

export const ScriptExecutionConsole = ({ script, isRunning }: ScriptExecutionConsoleProps) => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const consoleRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  useEffect(() => {
    if (isRunning) {
      // Simular logs en tiempo real
      const interval = setInterval(() => {
        addLog("INFO", `Ejecutando ${script.name}...`);
        
        setTimeout(() => {
          addLog("SUCCESS", "Script ejecutado exitosamente");
        }, 2000);
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [isRunning, script.name]);

  useEffect(() => {
    if (autoScroll && consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const addLog = (level: LogEntry["level"], message: string) => {
    const newLog: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      level,
      message
    };
    
    setLogs(prev => [...prev, newLog]);
  };

  const getLevelColor = (level: LogEntry["level"]) => {
    switch (level) {
      case "INFO": return "text-cyan-400";
      case "WARN": return "text-yellow-400";
      case "ERROR": return "text-red-400";
      case "SUCCESS": return "text-green-400";
      default: return "text-gray-400";
    }
  };

  const getLevelIcon = (level: LogEntry["level"]) => {
    switch (level) {
      case "INFO": return "ℹ️";
      case "WARN": return "⚠️";
      case "ERROR": return "❌";
      case "SUCCESS": return "✅";
      default: return "📋";
    }
  };

  const copyLogs = () => {
    const logsText = logs.map(log => 
      `[${log.timestamp}] ${log.level}: ${log.message}`
    ).join('\n');
    
    navigator.clipboard.writeText(logsText);
    toast({
      title: "Logs copiados",
      description: "Los logs han sido copiados al portapapeles"
    });
  };

  const downloadLogs = () => {
    const logsText = logs.map(log => 
      `[${log.timestamp}] ${log.level}: ${log.message}`
    ).join('\n');
    
    const blob = new Blob([logsText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${script.name}-logs-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card className="bg-gray-900 border-gray-700">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-cyan-400 flex items-center space-x-2">
            <Terminal className="w-5 h-5" />
            <span>Consola de Ejecución</span>
          </CardTitle>
          <div className="flex space-x-2">
            <Button
              size="sm"
              variant="outline"
              onClick={copyLogs}
              disabled={logs.length === 0}
              className="border-gray-600 text-gray-300"
            >
              <Copy className="w-4 h-4" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={downloadLogs}
              disabled={logs.length === 0}
              className="border-gray-600 text-gray-300"
            >
              <Download className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div 
          ref={consoleRef}
          className="bg-black p-4 rounded-lg h-64 overflow-y-auto font-mono text-sm"
        >
          {logs.length === 0 ? (
            <div className="text-gray-500 text-center py-8">
              Esperando ejecución del script...
            </div>
          ) : (
            logs.map((log, index) => (
              <div key={index} className="mb-1">
                <span className="text-gray-500">[{log.timestamp}]</span>
                <span className={`ml-2 ${getLevelColor(log.level)}`}>
                  {getLevelIcon(log.level)} {log.level}:
                </span>
                <span className="ml-2 text-white">{log.message}</span>
              </div>
            ))
          )}
        </div>
        
        <div className="mt-2 flex items-center justify-between text-sm text-gray-400">
          <span>{logs.length} líneas</span>
          <label className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded"
            />
            <span>Auto-scroll</span>
          </label>
        </div>
      </CardContent>
    </Card>
  );
};
