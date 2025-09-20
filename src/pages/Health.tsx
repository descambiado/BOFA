import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RefreshCw, CheckCircle, XCircle, AlertCircle, Activity } from "lucide-react";
import { APP_CONFIG } from "@/config/app";

interface HealthStatus {
  service: string;
  status: 'online' | 'offline' | 'warning';
  responseTime?: number;
  lastCheck: string;
  details?: string;
}

const Health = () => {
  const [healthData, setHealthData] = useState<HealthStatus[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const checkServices = async () => {
    setIsLoading(true);
    const services = [
      { name: 'API Backend', url: `${APP_CONFIG.api.baseUrl}/health` },
      { name: 'Script Executor', url: `${APP_CONFIG.api.baseUrl}/health/scripts` },
      { name: 'Lab Manager', url: `${APP_CONFIG.api.baseUrl}/health/labs` },
      { name: 'Database', url: `${APP_CONFIG.api.baseUrl}/health/database` }
    ];

    const results: HealthStatus[] = [];

    for (const service of services) {
      const startTime = Date.now();
      try {
        const response = await fetch(service.url, {
          signal: AbortSignal.timeout(5000)
        });
        const responseTime = Date.now() - startTime;
        
        if (response.ok) {
          const data = await response.json();
          results.push({
            service: service.name,
            status: responseTime > 2000 ? 'warning' : 'online',
            responseTime,
            lastCheck: new Date().toISOString(),
            details: data.details || 'Servicio funcionando correctamente'
          });
        } else {
          results.push({
            service: service.name,
            status: 'offline',
            lastCheck: new Date().toISOString(),
            details: `Error HTTP ${response.status}`
          });
        }
      } catch (error) {
        results.push({
          service: service.name,
          status: 'offline',
          lastCheck: new Date().toISOString(),
          details: error instanceof Error ? error.message : 'Conexión fallida'
        });
      }
    }

    setHealthData(results);
    setIsLoading(false);
  };

  useEffect(() => {
    checkServices();
    const interval = setInterval(checkServices, 30000);
    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'warning':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      case 'offline':
        return <XCircle className="w-5 h-5 text-red-500" />;
      default:
        return <Activity className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants = {
      online: 'bg-green-500/20 text-green-400 border-green-500/30',
      warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      offline: 'bg-red-500/20 text-red-400 border-red-500/30'
    };
    return variants[status as keyof typeof variants] || '';
  };

  return (
    <div className="container mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Estado del Sistema</h1>
          <p className="text-gray-400">Monitoreo en tiempo real de servicios BOFA v{APP_CONFIG.version}</p>
        </div>
        <Button 
          onClick={checkServices} 
          disabled={isLoading}
          className="bg-cyan-600 hover:bg-cyan-700"
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
          Actualizar
        </Button>
      </div>

      <div className="grid gap-6">
        {healthData.map((service, index) => (
          <Card key={index} className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  {getStatusIcon(service.status)}
                  <CardTitle className="text-white">{service.service}</CardTitle>
                </div>
                <Badge className={getStatusBadge(service.status)}>
                  {service.status.toUpperCase()}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                <div>
                  <p className="text-gray-400">Última verificación</p>
                  <p className="text-white font-medium">
                    {new Date(service.lastCheck).toLocaleTimeString()}
                  </p>
                </div>
                {service.responseTime && (
                  <div>
                    <p className="text-gray-400">Tiempo de respuesta</p>
                    <p className="text-white font-medium">{service.responseTime}ms</p>
                  </div>
                )}
                <div>
                  <p className="text-gray-400">Detalles</p>
                  <p className="text-white font-medium">{service.details}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="mt-8 bg-gray-800/30 border-gray-700">
        <CardHeader>
          <CardTitle className="text-cyan-400">Información del Sistema</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 text-sm">
            <div>
              <p className="text-gray-400">Versión</p>
              <p className="text-white font-medium">{APP_CONFIG.version}</p>
            </div>
            <div>
              <p className="text-gray-400">Codename</p>
              <p className="text-white font-medium">{APP_CONFIG.codename}</p>
            </div>
            <div>
              <p className="text-gray-400">Desarrollador</p>
              <p className="text-white font-medium">{APP_CONFIG.developer.name}</p>
            </div>
            <div>
              <p className="text-gray-400">Release Date</p>
              <p className="text-white font-medium">{APP_CONFIG.releaseDate}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Health;