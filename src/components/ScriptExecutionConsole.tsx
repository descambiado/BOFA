
import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Copy, Download, Terminal, Activity } from "lucide-react";
import { toast } from "sonner";
import { useWebSocket } from "@/hooks/useWebSocket";

interface Script {
  name: string;
  category: string;
}

interface ScriptExecutionConsoleProps {
  script: Script;
  isRunning: boolean;
  executionId: string | null;
}

export const ScriptExecutionConsole = ({ script, isRunning, executionId }: ScriptExecutionConsoleProps) => {
  const [output, setOutput] = useState<string[]>([]);
  const [executionTime, setExecutionTime] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<NodeJS.Timeout>();

  // WebSocket integration for real-time output
  const { messages, isConnected } = useWebSocket(executionId, {
    onMessage: (message) => {
      if (message.type === 'stdout' || message.type === 'stderr') {
        setOutput(prev => [...prev, message.data]);
      } else if (message.type === 'status') {
        const status = JSON.parse(message.data);
        setOutput(prev => [...prev, `[STATUS] ${status.status}: ${status.details?.message || ''}`]);
      } else if (message.type === 'completed') {
        const result = JSON.parse(message.data);
        setOutput(prev => [...prev, `[COMPLETED] Exit code: ${result.exit_code}`]);
      }
    }
  });

  useEffect(() => {
    if (isRunning) {
      // Clear previous output
      setOutput([]);
      setExecutionTime(0);
      
      // Timer for execution time
      intervalRef.current = setInterval(() => {
        setExecutionTime(prev => prev + 0.1);
      }, 100);
      
      return () => {
        if (intervalRef.current) clearInterval(intervalRef.current);
      };
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    }
  }, [isRunning]);

  useEffect(() => {
    // Auto-scroll al final
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [output]);

  const copyOutput = () => {
    const fullOutput = output.join('\n');
    navigator.clipboard.writeText(fullOutput);
    toast.success("Output copiado al portapapeles");
  };

  const downloadOutput = () => {
    const fullOutput = output.join('\n');
    const blob = new Blob([fullOutput], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${script.name}_output_${new Date().toISOString().slice(0,10)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Output descargado");
  };

  return (
    <Card className="bg-gray-800/50 border-gray-700 h-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <CardTitle className="text-cyan-400">Consola de Ejecución</CardTitle>
            {isRunning && (
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-green-400 animate-pulse" />
                <span className="text-green-400 text-sm">
                  {isConnected ? 'Ejecutando (Live)' : 'Conectando...'}
                </span>
              </div>
            )}
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-400">
              {executionTime.toFixed(1)}s
            </span>
            <Button
              size="sm"
              variant="outline"
              onClick={copyOutput}
              disabled={output.length === 0}
              className="border-gray-600 text-gray-300 hover:bg-gray-700"
            >
              <Copy className="w-4 h-4" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={downloadOutput}
              disabled={output.length === 0}
              className="border-gray-600 text-gray-300 hover:bg-gray-700"
            >
              <Download className="w-4 h-4" />
            </Button>
          </div>
        </div>
        <CardDescription>
          Output en tiempo real de la ejecución del script
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-96" ref={scrollRef}>
          <div className="font-mono text-sm space-y-1">
            {output.length === 0 && !isRunning && (
              <div className="text-gray-500 italic">
                Presiona "Ejecutar Script" para ver el output aquí...
              </div>
            )}
            {output.map((line, index) => (
              <div key={index} className={getLineColor(line)}>
                <span className="text-gray-500 mr-2">
                  {new Date().toLocaleTimeString()}
                </span>
                {line}
              </div>
            ))}
            {isRunning && (
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                <span className="text-cyan-400">Ejecutando...</span>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

const getLineColor = (line: string): string => {
  if (line.includes('[ERROR]') || line.includes('[CRITICAL]')) {
    return 'text-red-400';
  } else if (line.includes('[WARNING]') || line.includes('[ALERT]')) {
    return 'text-yellow-400';
  } else if (line.includes('[SUCCESS]') || line.includes('[FOUND]')) {
    return 'text-green-400';
  } else if (line.includes('[INFO]')) {
    return 'text-blue-400';
  } else if (line.includes('[ANALYSIS]') || line.includes('[SCAN]')) {
    return 'text-purple-400';
  } else if (line.includes('[ATTACK]') || line.includes('[EXPLOIT]')) {
    return 'text-red-300';
  } else if (line.includes('[DEFENSE]') || line.includes('[PROTECTION]')) {
    return 'text-green-300';
  } else {
    return 'text-gray-300';
  }
};
