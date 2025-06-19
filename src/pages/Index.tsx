import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  Terminal, 
  Shield, 
  Users, 
  BookOpen, 
  Play, 
  Github,
  Coffee,
  Zap,
  Target,
  Eye,
  Search,
  Clock,
  BarChart3,
  ArrowRight
} from "lucide-react";

const Index = () => {
  const features = [
    {
      icon: <Terminal className="w-8 h-8 text-red-400" />,
      title: "Red Team",
      description: "Arsenal ofensivo con técnicas avanzadas de penetración",
      count: "15+ herramientas",
      color: "border-red-500/20 bg-red-500/10",
      href: "/scripts"
    },
    {
      icon: <Shield className="w-8 h-8 text-blue-400" />,
      title: "Blue Team", 
      description: "Herramientas defensivas, monitoreo y análisis forense",
      count: "12+ herramientas",
      color: "border-blue-500/20 bg-blue-500/10",
      href: "/scripts"
    },
    {
      icon: <Users className="w-8 h-8 text-purple-400" />,
      title: "Purple Team",
      description: "Ejercicios coordinados de ataque y defensa",
      count: "8+ herramientas", 
      color: "border-purple-500/20 bg-purple-500/10",
      href: "/scripts"
    },
    {
      icon: <BookOpen className="w-8 h-8 text-green-400" />,
      title: "Modo Estudio",
      description: "Lecciones interactivas con validación automática",
      count: "10+ lecciones",
      color: "border-green-500/20 bg-green-500/10",
      href: "/study"
    },
    {
      icon: <Play className="w-8 h-8 text-orange-400" />,
      title: "Laboratorios",
      description: "Entornos Docker vulnerables para práctica segura",
      count: "8+ labs",
      color: "border-orange-500/20 bg-orange-500/10",
      href: "/labs"
    },
    {
      icon: <Clock className="w-8 h-8 text-cyan-400" />,
      title: "Historial",
      description: "Registro completo de ejecuciones y resultados",
      count: "Logging persistente",
      color: "border-cyan-500/20 bg-cyan-500/10",
      href: "/history"
    }
  ];

  const stats = [
    { label: "Scripts Totales", value: "50+", icon: <Zap className="w-5 h-5" /> },
    { label: "Laboratorios", value: "8+", icon: <Target className="w-5 h-5" /> },
    { label: "Lecciones", value: "10+", icon: <BookOpen className="w-5 h-5" /> },
    { label: "Ejecuciones", value: "∞", icon: <BarChart3 className="w-5 h-5" /> }
  ];

  const quickActions = [
    {
      title: "Escaneo Rápido",
      description: "Ghost Scanner sigiloso",
      action: "ghost_scanner.py",
      category: "Red Team",
      icon: <Search className="w-5 h-5" />
    },
    {
      title: "Análisis de Logs", 
      description: "Timeline Builder forense",
      action: "log_timeline_builder.py",
      category: "Blue Team",
      icon: <BarChart3 className="w-5 h-5" />
    },
    {
      title: "Simulación APT",
      description: "Threat Emulator",
      action: "threat_emulator.py", 
      category: "Purple Team",
      icon: <Users className="w-5 h-5" />
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white">
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-purple-500/10"></div>
        <div className="relative container mx-auto px-6 py-24">
          <div className="text-center max-w-4xl mx-auto">
            <Badge className="mb-6 bg-cyan-500/20 text-cyan-400 border-cyan-500 px-4 py-2 text-sm">
              v2.2.0 - UX Consolidation & Intelligence Layer
            </Badge>
            
            <h1 className="text-5xl md:text-7xl font-bold mb-6 bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
              BOFA Extended
            </h1>
            
            <p className="text-xl md:text-2xl text-gray-300 mb-4">
              Best Of All Cybersecurity Suite
            </p>
            
            <p className="text-lg text-gray-400 mb-8 max-w-2xl mx-auto">
              Plataforma completa de ciberseguridad: Red Team, Blue Team, Purple Team, 
              Análisis Forense, OSINT y Educación unificados en una suite ética y profesional.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Button 
                size="lg" 
                className="bg-gradient-to-r from-cyan-500 to-purple-500 hover:from-cyan-600 hover:to-purple-600 text-white font-semibold px-8 py-3"
                onClick={() => window.location.href = '/scripts'}
              >
                <Terminal className="w-5 h-5 mr-2" />
                Explorar Herramientas
              </Button>
              
              <Button 
                size="lg" 
                variant="outline" 
                className="border-gray-600 text-gray-300 hover:bg-gray-700 font-semibold px-8 py-3"
                onClick={() => window.location.href = '/study'}
              >
                <BookOpen className="w-5 h-5 mr-2" />
                Modo Estudio
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Section */}
      <div className="container mx-auto px-6 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          {stats.map((stat, index) => (
            <Card key={index} className="bg-gray-800/50 border-gray-700 text-center">
              <CardContent className="p-6">
                <div className="flex items-center justify-center mb-2 text-cyan-400">
                  {stat.icon}
                </div>
                <div className="text-2xl font-bold text-white mb-1">{stat.value}</div>
                <div className="text-sm text-gray-400">{stat.label}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Features Grid */}
      <div className="container mx-auto px-6 py-12">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-cyan-400 mb-4">Módulos Principales</h2>
          <p className="text-gray-400 max-w-2xl mx-auto">
            Cada módulo está diseñado para un propósito específico en el ecosistema de ciberseguridad
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => (
            <Card 
              key={index} 
              className={`${feature.color} border-gray-700 hover:scale-105 transition-all cursor-pointer group`}
              onClick={() => window.location.href = feature.href}
            >
              <CardHeader>
                <div className="flex items-center space-x-3">
                  {feature.icon}
                  <div>
                    <CardTitle className="text-white group-hover:text-cyan-400 transition-colors">
                      {feature.title}
                    </CardTitle>
                    <Badge variant="outline" className="mt-1 text-xs">
                      {feature.count}
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <CardDescription className="text-gray-300 mb-4">
                  {feature.description}
                </CardDescription>
                <div className="flex items-center text-cyan-400 text-sm font-medium">
                  Explorar <ArrowRight className="w-4 h-4 ml-1" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="container mx-auto px-6 py-12">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-cyan-400 mb-4">Acciones Rápidas</h2>
          <p className="text-gray-400">Herramientas más utilizadas para comenzar inmediatamente</p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {quickActions.map((action, index) => (
            <Card key={index} className="bg-gray-800/30 border-gray-700 hover:border-cyan-400 transition-all">
              <CardContent className="p-6">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="text-cyan-400">{action.icon}</div>
                  <div>
                    <h3 className="font-semibold text-white">{action.title}</h3>
                    <Badge variant="outline" className="text-xs">
                      {action.category}
                    </Badge>
                  </div>
                </div>
                <p className="text-gray-400 mb-4">{action.description}</p>
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="w-full border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black"
                  onClick={() => window.location.href = '/scripts'}
                >
                  Ejecutar
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Developer Section */}
      <div className="container mx-auto px-6 py-12">
        <Card className="bg-gradient-to-r from-gray-800/50 to-gray-700/50 border-gray-600">
          <CardContent className="p-8 text-center">
            <div className="flex items-center justify-center mb-4">
              <Coffee className="w-8 h-8 text-orange-400 mr-3" />
              <h3 className="text-2xl font-bold text-white">Desarrollado por @descambiado</h3>
            </div>
            <p className="text-gray-300 mb-6 max-w-2xl mx-auto">
              David Hernández Jiménez - Especialista en ciberseguridad con pasión por la educación 
              y el desarrollo de herramientas éticas para la comunidad.
            </p>
            <div className="flex justify-center space-x-4">
              <Button 
                variant="outline" 
                size="sm"
                className="border-gray-600 text-gray-300 hover:bg-gray-700"
                onClick={() => window.open('https://github.com/descambiado', '_blank')}
              >
                <Github className="w-4 h-4 mr-2" />
                GitHub
              </Button>
              <Button 
                variant="outline" 
                size="sm"
                className="border-gray-600 text-gray-300 hover:bg-gray-700"
                onClick={() => window.location.href = '/history'}
              >
                <Eye className="w-4 h-4 mr-2" />
                Ver Historial
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Footer */}
      <div className="border-t border-gray-800 py-8">
        <div className="container mx-auto px-6 text-center">
          <p className="text-gray-400">
            BOFA v2.2.0 - Best Of All Cybersecurity Suite | 
            Uso ético y educativo | MIT License
          </p>
        </div>
      </div>
    </div>
  );
};

export default Index;
