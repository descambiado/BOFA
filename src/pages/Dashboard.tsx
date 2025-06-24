
import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ActionButton } from "@/components/UI/ActionButton";
import { MetricCard } from "@/components/UI/MetricCard";
import { 
  Shield, 
  Terminal, 
  Users, 
  Search, 
  Smartphone, 
  Brain, 
  Clock, 
  Globe,
  TrendingUp,
  Activity,
  AlertTriangle,
  CheckCircle,
  Zap,
  Lock,
  Cloud,
  Eye
} from "lucide-react";
import { useNavigate } from "react-router-dom";

const Dashboard = () => {
  const navigate = useNavigate();

  const quickStats = [
    {
      title: "Scripts Ejecutados",
      value: "127",
      change: "+12%",
      trend: "up" as const,
      icon: <Terminal className="w-5 h-5" />
    },
    {
      title: "Amenazas Detectadas",
      value: "8",
      change: "-23%",
      trend: "down" as const,
      icon: <Shield className="w-5 h-5" />
    },
    {
      title: "Labs Activos",
      value: "3",
      change: "+1",
      trend: "up" as const,
      icon: <Activity className="w-5 h-5" />
    },
    {
      title: "Nivel de Seguridad",
      value: "94%",
      change: "+5%",
      trend: "up" as const,
      icon: <CheckCircle className="w-5 h-5" />
    }
  ];

  const recentActivities = [
    {
      id: 1,
      action: "AI Threat Hunter ejecutado",
      time: "hace 15 min",
      status: "success",
      module: "Blue Team"
    },
    {
      id: 2,
      action: "Supply Chain Scanner completado",
      time: "hace 32 min",
      status: "warning",
      module: "Red Team"
    },
    {
      id: 3,
      action: "Zero Trust Validator iniciado",
      time: "hace 1 hora",
      status: "running",
      module: "Purple Team"
    },
    {
      id: 4,
      action: "Quantum Crypto Analyzer finalizado",
      time: "hace 2 horas",
      status: "success",
      module: "Purple Team"
    }
  ];

  const newFeatures2025 = [
    {
      title: "🤖 AI Threat Hunter",
      description: "ML local + MITRE ATT&CK para detección avanzada",
      category: "Blue Team",
      status: "new"
    },
    {
      title: "🔗 Supply Chain Scanner",
      description: "Mapeo completo de cadenas de suministro",
      category: "Red Team", 
      status: "new"
    },
    {
      title: "🔮 Quantum Crypto Analyzer",
      description: "Evaluación post-cuántica de criptografía",
      category: "Purple Team",
      status: "new"
    },
    {
      title: "🎭 Deepfake Detection",
      description: "Motor de detección de contenido generado por IA",
      category: "Forensics",
      status: "new"
    },
    {
      title: "☁️ Cloud Native Attacks",
      description: "Simulador de ataques a contenedores y K8s",
      category: "Red Team",
      status: "new"
    },
    {
      title: "🛡️ Zero Trust Validator",
      description: "Validación de implementaciones Zero Trust",
      category: "Blue Team",
      status: "new"
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto max-w-7xl">
        {/* Banner de Bienvenida */}
        <div className="mb-8">
          <div className="bg-gradient-to-r from-cyan-600 to-purple-600 rounded-lg p-6 mb-6">
            <h1 className="text-3xl font-bold text-white mb-2">
              ¡Bienvenido a BOFA 2.5.0! 🚀
            </h1>
            <p className="text-cyan-100 text-lg">
              La plataforma de ciberseguridad más avanzada con tecnologías 2025
            </p>
            <div className="flex flex-wrap gap-2 mt-4">
              <Badge className="bg-white/20 text-white">AI/ML Integration</Badge>
              <Badge className="bg-white/20 text-white">Post-Quantum Ready</Badge>
              <Badge className="bg-white/20 text-white">Zero Trust Validation</Badge>
              <Badge className="bg-white/20 text-white">Supply Chain Security</Badge>
            </div>
          </div>
        </div>

        {/* Métricas Rápidas */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {quickStats.map((stat, index) => (
            <MetricCard
              key={index}
              title={stat.title}
              value={stat.value}
              change={stat.change}
              trend={stat.trend}
              icon={stat.icon}
            />
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Acceso Rápido */}
          <div className="lg:col-span-2">
            <Card className="bg-gray-800/50 border-gray-700">
              <CardHeader>
                <CardTitle className="text-cyan-400">🚀 Acceso Rápido</CardTitle>
                <CardDescription>Herramientas principales de BOFA</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <ActionButton
                    icon={<Terminal className="w-5 h-5" />}
                    title="Scripts"
                    description="Ejecutar herramientas"
                    onClick={() => navigate('/scripts')}
                  />
                  <ActionButton
                    icon={<Eye className="w-5 h-5" />}
                    title="Laboratorios"
                    description="Entornos de práctica"
                    onClick={() => navigate('/labs')}
                  />
                  <ActionButton
                    icon={<Clock className="w-5 h-5" />}
                    title="Historial"
                    description="Ver ejecuciones"
                    onClick={() => navigate('/history')}
                  />
                  <ActionButton
                    icon={<Brain className="w-5 h-5" />}
                    title="AI Hunter"
                    description="Detección IA"
                    onClick={() => navigate('/scripts')}
                  />
                  <ActionButton
                    icon={<Shield className="w-5 h-5" />}
                    title="Zero Trust"
                    description="Validación ZT"
                    onClick={() => navigate('/scripts')}
                  />
                  <ActionButton
                    icon={<Lock className="w-5 h-5" />}
                    title="Quantum"
                    description="Crypto post-cuántica"
                    onClick={() => navigate('/scripts')}
                  />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Actividad Reciente */}
          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="text-cyan-400">📊 Actividad Reciente</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentActivities.map((activity) => (
                  <div key={activity.id} className="flex items-center space-x-3 p-3 bg-gray-700/50 rounded-lg">
                    <div className={`w-3 h-3 rounded-full ${
                      activity.status === 'success' ? 'bg-green-400' :
                      activity.status === 'warning' ? 'bg-yellow-400' : 
                      activity.status === 'running' ? 'bg-blue-400 animate-pulse' : 'bg-red-400'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-white truncate">{activity.action}</p>
                      <p className="text-xs text-gray-400">{activity.time} • {activity.module}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Novedades 2025 */}
        <Card className="bg-gray-800/50 border-gray-700 mb-8">
          <CardHeader>
            <CardTitle className="text-cyan-400">✨ Novedades 2025</CardTitle>
            <CardDescription>Las últimas incorporaciones tecnológicas</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {newFeatures2025.map((feature, index) => (
                <div key={index} className="p-4 bg-gradient-to-br from-gray-700/50 to-gray-800/50 rounded-lg border border-gray-600 hover:border-cyan-400 transition-all">
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="font-semibold text-white">{feature.title}</h4>
                    <Badge className="bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-xs">
                      NUEVO
                    </Badge>
                  </div>
                  <p className="text-sm text-gray-300 mb-3">{feature.description}</p>
                  <Badge variant="outline" className="text-xs border-gray-500 text-gray-400">
                    {feature.category}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Footer del Dashboard */}
        <Card className="bg-gray-800/50 border-gray-700">
          <CardContent className="p-6 text-center">
            <div className="flex items-center justify-center space-x-2 mb-4">
              <Zap className="w-5 h-5 text-cyan-400" />
              <span className="text-cyan-400 font-semibold">BOFA Extended Systems v2.5.0</span>
            </div>
            <p className="text-gray-400 text-sm">
              Desarrollado por @descambiado • Plataforma integral de ciberseguridad con tecnologías 2025
            </p>
            <div className="flex justify-center space-x-4 mt-4 text-xs text-gray-500">
              <span>🤖 AI/ML Ready</span>
              <span>🔮 Post-Quantum</span>
              <span>☁️ Cloud Native</span>
              <span>🛡️ Zero Trust</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Dashboard;
