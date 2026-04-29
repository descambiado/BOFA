
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Download, FileText, FileSpreadsheet, Code, Globe } from "lucide-react";
import { toast } from "sonner";

interface ExecutionData {
  script: string;
  module: string;
  parameters: Record<string, any>;
  output: string;
  timestamp: string;
  executionTime: string;
  status: string;
}

interface ReportExporterProps {
  executionData: ExecutionData;
}

export const ReportExporter = ({ executionData }: ReportExporterProps) => {
  const [isExporting, setIsExporting] = useState(false);

  const generateReport = (format: 'json' | 'csv' | 'txt' | 'html') => {
    setIsExporting(true);
    
    try {
      let content = '';
      let filename = `bofa-report-${executionData.script}-${new Date().toISOString().slice(0,10)}`;
      let mimeType = '';

      switch (format) {
        case 'json':
          content = JSON.stringify({
            metadata: {
              script: executionData.script,
              module: executionData.module,
              timestamp: executionData.timestamp,
              executionTime: executionData.executionTime,
              status: executionData.status,
              generator: "BOFA Professional Suite v2.5.0"
            },
            parameters: executionData.parameters,
            results: {
              output: executionData.output,
              status: executionData.status
            }
          }, null, 2);
          filename += '.json';
          mimeType = 'application/json';
          break;

        case 'csv':
          content = `Script,Module,Timestamp,ExecutionTime,Status,Parameters,Output\n`;
          content += `"${executionData.script}","${executionData.module}","${executionData.timestamp}","${executionData.executionTime}","${executionData.status}","${JSON.stringify(executionData.parameters).replace(/"/g, '""')}","${executionData.output.replace(/"/g, '""')}"`;
          filename += '.csv';
          mimeType = 'text/csv';
          break;

        case 'txt':
          content = `BOFA Professional Suite v2.5.0 - Reporte de Ejecución
============================================================

Script: ${executionData.script}
Módulo: ${executionData.module}
Timestamp: ${executionData.timestamp}
Tiempo de Ejecución: ${executionData.executionTime}
Estado: ${executionData.status}

Parámetros:
${JSON.stringify(executionData.parameters, null, 2)}

Salida del Script:
${executionData.output}

============================================================
Generado por BOFA Professional Suite v2.5.0
`;
          filename += '.txt';
          mimeType = 'text/plain';
          break;

        case 'html':
          content = `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte BOFA - ${executionData.script}</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 20px; background: #1a1a1a; color: #00ff00; }
        .header { border-bottom: 2px solid #00ff00; padding-bottom: 10px; margin-bottom: 20px; }
        .section { margin: 20px 0; }
        .output { background: #000; padding: 15px; border: 1px solid #00ff00; white-space: pre-wrap; }
        .meta { color: #00ffff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 BOFA Professional Suite v2.5.0</h1>
        <h2>Reporte de Ejecución: ${executionData.script}</h2>
    </div>
    
    <div class="section">
        <h3 class="meta">Información General</h3>
        <p><strong>Script:</strong> ${executionData.script}</p>
        <p><strong>Módulo:</strong> ${executionData.module}</p>
        <p><strong>Timestamp:</strong> ${executionData.timestamp}</p>
        <p><strong>Tiempo de Ejecución:</strong> ${executionData.executionTime}</p>
        <p><strong>Estado:</strong> ${executionData.status}</p>
    </div>

    <div class="section">
        <h3 class="meta">Parámetros</h3>
        <div class="output">${JSON.stringify(executionData.parameters, null, 2)}</div>
    </div>

    <div class="section">
        <h3 class="meta">Salida del Script</h3>
        <div class="output">${executionData.output}</div>
    </div>

    <div class="section">
        <p><em>Generado por BOFA Professional Suite v2.5.0 - ${new Date().toLocaleString()}</em></p>
    </div>
</body>
</html>`;
          filename += '.html';
          mimeType = 'text/html';
          break;
      }

      // Crear y descargar el archivo
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast.success(`Reporte ${format.toUpperCase()} descargado exitosamente`);
    } catch (error) {
      toast.error(`Error al generar reporte ${format.toUpperCase()}`);
      console.error('Export error:', error);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button 
          variant="outline" 
          size="sm" 
          disabled={isExporting}
          className="border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black"
        >
          <Download className="w-4 h-4 mr-2" />
          {isExporting ? 'Exportando...' : 'Exportar Reporte'}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="bg-gray-800 border-gray-700">
        <DropdownMenuItem 
          onClick={() => generateReport('json')}
          className="text-gray-300 hover:bg-gray-700 hover:text-white cursor-pointer"
        >
          <Code className="w-4 h-4 mr-2" />
          JSON (Estructurado)
        </DropdownMenuItem>
        <DropdownMenuItem 
          onClick={() => generateReport('csv')}
          className="text-gray-300 hover:bg-gray-700 hover:text-white cursor-pointer"
        >
          <FileSpreadsheet className="w-4 h-4 mr-2" />
          CSV (Excel)
        </DropdownMenuItem>
        <DropdownMenuItem 
          onClick={() => generateReport('txt')}
          className="text-gray-300 hover:bg-gray-700 hover:text-white cursor-pointer"
        >
          <FileText className="w-4 h-4 mr-2" />
          TXT (Plano)
        </DropdownMenuItem>
        <DropdownMenuItem 
          onClick={() => generateReport('html')}
          className="text-gray-300 hover:bg-gray-700 hover:text-white cursor-pointer"
        >
          <Globe className="w-4 h-4 mr-2" />
          HTML (Web)
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
