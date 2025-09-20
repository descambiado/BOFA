
import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/UI/StatusBadge";
import { ActionButton } from "@/components/UI/ActionButton";
import { useLabs } from "@/services/api";
import { 
  Beaker, 
  Play, 
  Square, 
  Settings,
  Monitor,
  Smartphone,
  Cloud,
  Shield,
  Zap,
  Users
} from "lucide-react";

interface Lab {
  id: string;
  name: string;
  description: string;
  category: string;
  difficulty: string;
  status: 'stopped' | 'running' | 'starting' | 'error';
  port?: number;
  url?: string;
  estimatedTime: string;
  technologies: string[];
}

const Labs = () => {
  const [labs, setLabs] = useState<Lab[]>([
    {
      id: "internal-network",
      name: "Red Interna Corporativa",
      description: "Simula una red corporativa completa con AD, servidores web y bases de datos",
      category: "network",
      difficulty: "intermediate",
      status: "stopped",
      port: 8080,
      estimatedTime: "45-60 min",
      technologies: ["Active Directory", "Windows Server", "Apache", "MySQL"]
    },
    {
      id: "android-emulation",
      name: "Android Security Lab",
      description: "Emulador Android con aplicaciones vulnerables para análisis móvil",
      category: "mobile",
      difficulty: "advanced",
      status: "running",
      port: 5554,
      url: "http://localhost:5554",
      estimatedTime: "30-45 min",
      technologies: ["Android", "APK Analysis", "Frida", "ADB"]
    },
    {
      id: "cloud-misconfig",
      name: "Cloud Misconfiguration",
      description: "Infraestructura cloud con configuraciones erróneas comunes",
      category: "cloud",
      difficulty: "beginner",
      status: "stopped",
      estimatedTime: "20-30 min",
      technologies: ["AWS", "S3", "IAM", "CloudTrail"]
    },
    {
      id: "ctf-generator",
      name: "CTF Challenge Generator",
      description: "Generador automático de retos CTF personalizables",
      category: "ctf",
      difficulty: "intermediate",
      status: "stopped",
      estimatedTime: "Variable",
      technologies: ["Python", "Docker", "Web Challenges", "Crypto"]
    }
  ]);

  const getCategoryIcon = (category: string) => {
    const icons = {
      network: Monitor,
      mobile: Smartphone,
      cloud: Cloud,
      ctf: Zap,
      web: Shield,
      purple: Users
    };
    return icons[category as keyof typeof icons] || Beaker;
  };

  const getDifficultyColor = (difficulty: string) => {
    const colors = {
      beginner: "bg-green-500",
      intermediate: "bg-yellow-500",
      advanced: "bg-red-500"
    };
    return colors[difficulty as keyof typeof colors] || "bg-gray-500";
  };

  const handleLabAction = (labId: string, action: 'start' | 'stop' | 'restart') => {
    setLabs(prev => prev.map(lab => {
      if (lab.id === labId) {
        if (action === 'start') {
          return { ...lab, status: 'starting' as const };
        } else if (action === 'stop') {
          return { ...lab, status: 'stopped' as const };
        }
      }
      return lab;
    }));

    // Simulate lab startup/shutdown
    if (action === 'start') {
      setTimeout(() => {
        setLabs(prev => prev.map(lab => 
          lab.id === labId ? { ...lab, status: 'running' as const, url: `http://localhost:${lab.port}` } : lab
        ));
      }, 3000);
    }
  };

  return (
    <div className="container mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-cyan-400 mb-2">🧪 Laboratorios de Práctica</h1>
        <p className="text-gray-300">
          Entornos controlados para practicar técnicas de ciberseguridad de forma segura
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <Card className="bg-gray-800/50 border-gray-700">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-cyan-400">{labs.length}</div>
            <div className="text-sm text-gray-400">Labs Disponibles</div>
          </CardContent>
        </Card>
        <Card className="bg-gray-800/50 border-gray-700">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-green-400">
              {labs.filter(l => l.status === 'running').length}
            </div>
            <div className="text-sm text-gray-400">Activos</div>
          </CardContent>
        </Card>
        <Card className="bg-gray-800/50 border-gray-700">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-yellow-400">
              {labs.filter(l => l.difficulty === 'intermediate').length}
            </div>
            <div className="text-sm text-gray-400">Intermedios</div>
          </CardContent>
        </Card>
        <Card className="bg-gray-800/50 border-gray-700">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-red-400">
              {labs.filter(l => l.difficulty === 'advanced').length}
            </div>
            <div className="text-sm text-gray-400">Avanzados</div>
          </CardContent>
        </Card>
      </div>

      {/* Labs Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {labs.map((lab) => {
          const CategoryIcon = getCategoryIcon(lab.category);
          
          return (
            <Card key={lab.id} className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <CategoryIcon className="w-8 h-8 text-cyan-400" />
                    <div>
                      <CardTitle className="text-cyan-400">{lab.name}</CardTitle>
                      <CardDescription className="text-gray-300 mt-1">
                        {lab.description}
                      </CardDescription>
                    </div>
                  </div>
                  <StatusBadge status={lab.status} />
                </div>
              </CardHeader>
              
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <Badge className={`${getDifficultyColor(lab.difficulty)} text-white`}>
                    {lab.difficulty}
                  </Badge>
                  <span className="text-sm text-gray-400">⏱️ {lab.estimatedTime}</span>
                </div>

                <div className="space-y-2">
                  <div className="text-sm text-gray-400">Tecnologías:</div>
                  <div className="flex flex-wrap gap-2">
                    {lab.technologies.map((tech) => (
                      <Badge key={tech} variant="outline" className="text-xs border-gray-600 text-gray-300">
                        {tech}
                      </Badge>
                    ))}
                  </div>
                </div>

                {lab.status === 'running' && lab.url && (
                  <div className="bg-gray-900 p-3 rounded-lg">
                    <div className="text-sm text-gray-400 mb-1">URL de Acceso:</div>
                    <a 
                      href={lab.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:text-cyan-300 font-mono text-sm"
                    >
                      {lab.url}
                    </a>
                  </div>
                )}

                <div className="flex items-center space-x-3">
                  {lab.status === 'stopped' && (
                    <ActionButton
                      icon={<Play className="w-4 h-4" />}
                      title="Iniciar Lab"
                      description="Iniciar laboratorio"
                      onClick={() => handleLabAction(lab.id, 'start')}
                      className="bg-green-600 hover:bg-green-700 flex-1"
                    />
                  )}
                  
                  {lab.status === 'starting' && (
                    <Button disabled className="flex-1">
                      <div className="animate-spin w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full mr-2"></div>
                      Iniciando...
                    </Button>
                  )}
                  
                  {lab.status === 'running' && (
                    <>
                      <ActionButton
                        icon={<Square className="w-4 h-4" />}
                        title="Detener"
                        description="Detener laboratorio"
                        onClick={() => handleLabAction(lab.id, 'stop')}
                        className="bg-red-600 hover:bg-red-700 flex-1"
                      />
                      <ActionButton
                        icon={<Settings className="w-4 h-4" />}
                        title="Configurar"
                        description="Configurar laboratorio"
                        onClick={() => {}}
                      />
                    </>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Quick Start Guide */}
      <Card className="bg-gray-800/50 border-gray-700 mt-8">
        <CardHeader>
          <CardTitle className="text-cyan-400">🚀 Guía Rápida</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div>
              <h4 className="text-green-400 font-semibold mb-2">1. Selecciona un Lab</h4>
              <p className="text-gray-400">Elige según tu nivel y área de interés</p>
            </div>
            <div>
              <h4 className="text-yellow-400 font-semibold mb-2">2. Inicia el Entorno</h4>
              <p className="text-gray-400">Los contenedores se configuran automáticamente</p>
            </div>
            <div>
              <h4 className="text-cyan-400 font-semibold mb-2">3. Practica Seguro</h4>
              <p className="text-gray-400">Experimenta sin riesgo en entornos aislados</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Labs;
