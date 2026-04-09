
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { LoginDialog } from "@/components/auth/LoginDialog";
import { authService } from "@/services/api";
import { APP_CONFIG } from "@/config/app";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/UI/card";
import { Button } from "@/components/UI/button";
import { Badge } from "@/components/UI/badge";
import { ActionButton } from "@/components/UI/ActionButton";
import { 
  Shield, 
  Terminal, 
  Users, 
  Search, 
  Smartphone, 
  Brain, 
  Clock, 
  Globe,
  Play,
  TrendingUp,
  Zap,
  Lock,
  Cloud,
  Eye,
  BookOpen,
  ChevronRight
} from "lucide-react";

const Index = () => {
  const navigate = useNavigate();
  const [showLogin, setShowLogin] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(authService.isAuthenticated());

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    authService.logout();
    setIsAuthenticated(false);
  };

  const modules = [
    {
      id: "red",
      name: "Red Team",
      description: "Arsenal ofensivo + Supply Chain + Cloud Native",
      icon: <Terminal className="w-8 h-8" />,
      count: 18,
      color: "from-red-600 to-red-800"
    },
    {
      id: "blue", 
      name: "Blue Team",
      description: "Defensiva + AI Threat Hunting + Zero Trust",
      icon: <Shield className="w-8 h-8" />,
      count: 15,
      color: "from-blue-600 to-blue-800"
    },
    {
      id: "purple",
      name: "Purple Team", 
      description: "Coordinado + Quantum-Safe + Behavioral",
      icon: <Users className="w-8 h-8" />,
      count: 10,
      color: "from-purple-600 to-purple-800"
    },
    {
      id: "forensics",
      name: "Forense",
      description: "Investigación + Deepfake Detection + Timeline",
      icon: <Search className="w-8 h-8" />,
      count: 12,
      color: "from-green-600 to-green-800"
    }
  ];

  const features2025 = [
    "🤖 AI/ML Integration",
    "🔮 Post-Quantum Ready", 
    "🔗 Supply Chain Security",
    "🛡️ Zero Trust Validation",
    "☁️ Cloud Native Attacks",
    "🎭 Deepfake Detection",
    "🏭 IoT Security Mapping"
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white">
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-600/20 to-purple-600/20"></div>
        <div className="relative container mx-auto px-6 py-20 text-center">
          <div className="space-y-6">
            <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-cyan-600 to-purple-600 px-4 py-2 rounded-full text-sm font-medium animate-pulse">
              <Zap className="w-4 h-4" />
              <span>NUEVO: {APP_CONFIG.fullName} v{APP_CONFIG.version}</span>
            </div>
            
            <h1 className="text-5xl md:text-7xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
              BOFA 2025
            </h1>
            
            <p className="text-xl md:text-2xl text-gray-300 max-w-3xl mx-auto">
              La plataforma de ciberseguridad más avanzada del mundo
              <br />
              <span className="text-cyan-400 font-semibold">Con tecnologías de próxima generación</span>
            </p>
            
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              {features2025.map((feature, index) => (
                <Badge key={index} className="px-3 py-1 bg-gray-800/50 border-cyan-400/30 text-cyan-300">
                  {feature}
                </Badge>
              ))}
            </div>

            {isAuthenticated ? (
              <div className="flex flex-col sm:flex-row gap-4 justify-center mt-12">
                <Button
                  size="lg"
                  onClick={() => navigate('/dashboard')}
                  className="bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-700 hover:to-purple-700 text-white px-8 py-4 text-lg"
                >
                  <Play className="w-5 h-5 mr-2" />
                  Ir al Dashboard
                </Button>
                <Button
                  size="lg"
                  variant="outline"
                  onClick={() => navigate('/scripts')}
                  className="border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black px-8 py-4 text-lg"
                >
                  <Terminal className="w-5 h-5 mr-2" />
                  Explorar Scripts
                </Button>
                <Button 
                  variant="outline"
                  size="lg"
                  onClick={handleLogout}
                  className="border-red-400 text-red-400 hover:bg-red-400 hover:text-black px-8 py-4 text-lg"
                >
                  Cerrar Sesión ({authService.getCurrentUser()?.username})
                </Button>
              </div>
            ) : (
              <Button 
                size="lg" 
                className="bg-gradient-to-r from-cyan-500 to-purple-500 hover:from-cyan-600 hover:to-purple-600 text-white font-medium px-8 py-4 rounded-xl transform transition-all duration-300 hover:scale-105 hover:shadow-xl text-lg"
                onClick={() => setShowLogin(true)}
              >
                Iniciar Sesión
                <ChevronRight className="ml-2 h-5 w-5" />
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Modules Overview */}
      <div className="container mx-auto px-6 py-16">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-cyan-400 mb-4">Módulos Principales</h2>
          <p className="text-gray-300 text-lg">Herramientas especializadas para cada necesidad</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {modules.map((module) => (
            <Card key={module.id} className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all transform hover:scale-105 cursor-pointer">
              <CardHeader>
                <div className={`w-16 h-16 rounded-lg bg-gradient-to-br ${module.color} flex items-center justify-center text-white mb-4`}>
                  {module.icon}
                </div>
                <CardTitle className="text-cyan-400">{module.name}</CardTitle>
                <CardDescription className="text-gray-300">
                  {module.description}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-white">{module.count}</span>
                  <span className="text-sm text-gray-400">herramientas</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Innovation Highlights */}
      <div className="bg-gradient-to-r from-gray-800/50 to-gray-900/50 py-16">
        <div className="container mx-auto px-6">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-cyan-400 mb-4">🚀 Innovaciones 2025</h2>
            <p className="text-gray-300 text-lg">Tecnologías de vanguardia integradas</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="text-center space-y-4">
              <div className="w-20 h-20 bg-gradient-to-br from-cyan-600 to-blue-600 rounded-full flex items-center justify-center mx-auto">
                <Brain className="w-10 h-10 text-white" />
              </div>
              <h3 className="text-xl font-bold text-white">AI/ML Integration</h3>
              <p className="text-gray-400">Modelos locales de IA para detección avanzada de amenazas y análisis comportamental</p>
            </div>

            <div className="text-center space-y-4">
              <div className="w-20 h-20 bg-gradient-to-br from-purple-600 to-pink-600 rounded-full flex items-center justify-center mx-auto">
                <Lock className="w-10 h-10 text-white" />
              </div>
              <h3 className="text-xl font-bold text-white">Post-Quantum Crypto</h3>
              <p className="text-gray-400">Evaluación y migración hacia algoritmos resistentes a computación cuántica</p>
            </div>

            <div className="text-center space-y-4">
              <div className="w-20 h-20 bg-gradient-to-br from-green-600 to-teal-600 rounded-full flex items-center justify-center mx-auto">
                <Cloud className="w-10 h-10 text-white" />
              </div>
              <h3 className="text-xl font-bold text-white">Cloud Native Security</h3>
              <p className="text-gray-400">Herramientas especializadas para contenedores, Kubernetes y arquitecturas serverless</p>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="container mx-auto px-6 py-16">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-cyan-400 mb-4">Acceso Rápido</h2>
          <p className="text-gray-300 text-lg">Comienza inmediatamente con las herramientas principales</p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-4xl mx-auto">
          <ActionButton
            icon={<Terminal className="w-6 h-6" />}
            title="Scripts"
            description="Ejecutar herramientas"
            onClick={() => navigate('/scripts')}
          />
          <ActionButton
            icon={<Eye className="w-6 h-6" />}
            title="Labs" 
            description="Práctica segura"
            onClick={() => navigate('/labs')}
          />
          <ActionButton
            icon={<Clock className="w-6 h-6" />}
            title="Historial"
            description="Ver actividad"
            onClick={() => navigate('/history')}
          />
          <ActionButton
            icon={<BookOpen className="w-6 h-6" />}
            title="Estudiar"
            description="Aprender"
            onClick={() => navigate('/study')}
          />
        </div>
      </div>

      {/* Loading Animation */}
      <div className="text-center py-8">
        <div className="inline-flex items-center space-x-2 text-cyan-400">
          <div className="animate-spin w-5 h-5 border-2 border-cyan-400 border-t-transparent rounded-full"></div>
          <span>Cargando Dashboard...</span>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-gray-900/50 border-t border-gray-700 py-8">
        <div className="container mx-auto px-6 text-center">
          <div className="flex items-center justify-center space-x-2 mb-4">
            <Zap className="w-5 h-5 text-cyan-400" />
            <span className="text-cyan-400 font-semibold">{APP_CONFIG.fullName} v{APP_CONFIG.version}</span>
          </div>
          <p className="text-gray-400 mb-4">
            Desarrollado por {APP_CONFIG.developer.name} • La plataforma de ciberseguridad más completa del mundo
          </p>
          <div className="flex justify-center space-x-6 text-sm text-gray-500">
            <span>🤖 AI Ready</span>
            <span>🔮 Quantum Safe</span>
            <span>☁️ Cloud Native</span>
            <span>🛡️ Zero Trust</span>
          </div>
        </div>
      </footer>

      <LoginDialog 
        open={showLogin} 
        onOpenChange={setShowLogin}
        onSuccess={handleLoginSuccess}
      />
    </div>
  );
};

export default Index;
