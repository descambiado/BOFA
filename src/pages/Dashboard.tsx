
import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ActionButton } from "@/components/UI/ActionButton";
import { MetricCard } from "@/components/UI/MetricCard";
import { useDashboardStats } from "@/services/api";
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
  const { data: stats, isLoading } = useDashboardStats();

  const quickStats = stats ? [
    {
      title: "Scripts Ejecutados",
      value: stats.executions?.total_executions?.toString() || "0",
      change: "+12%",
      trend: "up" as const,
      icon: <Terminal className="w-5 h-5" />
    },
    {
      title: "Ejecuciones Exitosas",
      value: stats.executions?.successful?.toString() || "0",
      change: stats.executions?.success_rate ? `${stats.executions.success_rate}%` : "0%",
      trend: "up" as const,
      icon: <CheckCircle className="w-5 h-5" />
    },
    {
      title: "Labs Activos",
      value: stats.docker?.active_labs?.toString() || "0",
      change: "+1",
      trend: "up" as const,
      icon: <Activity className="w-5 h-5" />
    },
    {
      title: "Uso de CPU",
      value: `${stats.system?.cpu_percent || 0}%`,
      change: stats.system?.cpu_percent > 70 ? "Alto" : "Normal",
      trend: stats.system?.cpu_percent > 70 ? "down" as const : "up" as const,
      icon: <Shield className="w-5 h-5" />
    }
  ] : [];

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
    <div className="relative min-h-screen p-6 animate-fade-in">
      <div className="container mx-auto max-w-7xl">
        {/* Banner de Bienvenida */}
        <div className="mb-8">
          <div className="bofa-card-dark bg-gradient-cyber rounded-xl p-8 mb-6 hover-glow border-primary/20 relative overflow-hidden">
            {/* Animated Background Pattern */}
            <div className="absolute inset-0 opacity-10">
              <div className="absolute w-32 h-32 bg-white rounded-full -top-16 -right-16 animate-float"></div>
              <div className="absolute w-20 h-20 bg-white rounded-full -bottom-10 -left-10 animate-bounce-slow"></div>
            </div>
            
            <div className="relative z-10">
              <h1 className="text-4xl font-bold text-white mb-3 font-cyber">
                ¡Bienvenido a BOFA v2.5.1! 🚀
              </h1>
              <p className="text-white/90 text-xl mb-4">
                La plataforma de ciberseguridad más avanzada con tecnologías 2025
              </p>
              <p className="text-white/70 text-sm mb-6">
                Desarrollado por @descambiado • Neural Security Edge
              </p>
              <div className="flex flex-wrap gap-3">
                <Badge className="bg-white/20 text-white border-white/30 px-3 py-1 hover-lift">
                  🤖 AI/ML Integration
                </Badge>
                <Badge className="bg-white/20 text-white border-white/30 px-3 py-1 hover-lift">
                  🔮 Post-Quantum Ready
                </Badge>
                <Badge className="bg-white/20 text-white border-white/30 px-3 py-1 hover-lift">
                  🛡️ Zero Trust Validation
                </Badge>
                <Badge className="bg-white/20 text-white border-white/30 px-3 py-1 hover-lift">
                  🔗 Supply Chain Security
                </Badge>
                <Badge className="bg-white/20 text-white border-white/30 px-3 py-1 hover-lift">
                  🧠 Neural Edge Computing
                </Badge>
              </div>
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
            <Card className="bofa-card-dark border-primary/20 hover-glow">
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
          <Card className="bofa-card-dark border-primary/20 hover-glow">
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
        <Card className="bofa-card-dark border-primary/20 hover-glow mb-8">
          <CardHeader>
            <CardTitle className="text-primary">✨ Novedades Neural Security Edge</CardTitle>
            <CardDescription>Las últimas incorporaciones tecnológicas revolucionarias</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {newFeatures2025.map((feature, index) => (
                <div key={index} className="p-4 bofa-card-dark border-primary/10 hover-lift hover:border-primary/30 transition-all duration-300 group">
                  <div className="flex items-start justify-between mb-3">
                    <h4 className="font-semibold text-foreground group-hover:text-primary transition-colors">
                      {feature.title}
                    </h4>
                    <Badge className="bg-gradient-cyber text-white text-xs animate-pulse">
                      NUEVO
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mb-3 group-hover:text-foreground transition-colors">
                    {feature.description}
                  </p>
                  <Badge variant="outline" className="text-xs border-primary/30 text-primary">
                    {feature.category}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Footer del Dashboard */}
        <Card className="bofa-card-dark border-primary/20 hover-glow">
          <CardContent className="p-6 text-center">
            <div className="flex items-center justify-center space-x-2 mb-4">
              <Zap className="w-6 h-6 text-primary animate-glow" />
              <span className="text-primary font-bold text-lg">BOFA Neural Security Edge v2.5.1</span>
            </div>
            <p className="text-muted-foreground text-sm mb-4">
              Desarrollado por @descambiado • La plataforma de ciberseguridad más avanzada del universo
            </p>
            <div className="flex flex-wrap justify-center gap-4 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                🤖 <span className="text-primary">AI/ML Ready</span>
              </span>
              <span className="flex items-center gap-1">
                🔮 <span className="text-secondary">Post-Quantum</span>
              </span>
              <span className="flex items-center gap-1">
                ☁️ <span className="text-accent">Cloud Native</span>
              </span>
              <span className="flex items-center gap-1">
                🛡️ <span className="text-success">Zero Trust</span>
              </span>
              <span className="flex items-center gap-1">
                🧠 <span className="text-warning">Neural Edge</span>
              </span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Dashboard;
