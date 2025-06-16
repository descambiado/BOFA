
import { Shield, Terminal, Globe, Lock, Eye, Wrench } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const Index = () => {
  const modules = [
    {
      icon: <Eye className="w-8 h-8" />,
      title: "Reconocimiento",
      description: "Herramientas de descubrimiento y enumeración",
      color: "bg-blue-500"
    },
    {
      icon: <Terminal className="w-8 h-8" />,
      title: "Explotación",
      description: "Generadores de payloads y exploits",
      color: "bg-red-500"
    },
    {
      icon: <Globe className="w-8 h-8" />,
      title: "OSINT",
      description: "Inteligencia de fuentes abiertas",
      color: "bg-green-500"
    },
    {
      icon: <Shield className="w-8 h-8" />,
      title: "Blue Team",
      description: "Herramientas defensivas y monitoreo",
      color: "bg-purple-500"
    },
    {
      icon: <Lock className="w-8 h-8" />,
      title: "Análisis Malware",
      description: "Herramientas de análisis estático",
      color: "bg-orange-500"
    },
    {
      icon: <Wrench className="w-8 h-8" />,
      title: "Docker Labs",
      description: "Entornos de práctica y simulación",
      color: "bg-cyan-500"
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white">
      {/* Header */}
      <header className="border-b border-gray-700 bg-black/50 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-10 h-10 text-cyan-400" />
              <div>
                <h1 className="text-2xl font-bold text-cyan-400">BOFA</h1>
                <p className="text-sm text-gray-400">Best Of All Cybersecurity Suite</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-sm text-gray-400">Desarrollado por</p>
              <p className="text-cyan-400 font-semibold">@descambiado</p>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20">
        <div className="container mx-auto px-4 text-center">
          <div className="max-w-4xl mx-auto">
            <h2 className="text-5xl font-bold mb-6 bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Suite Profesional de Ciberseguridad
            </h2>
            <p className="text-xl text-gray-300 mb-8 leading-relaxed">
              BOFA es una plataforma integral que combina herramientas de pentesting, OSINT, 
              análisis de malware, y defensa cibernética en un solo ecosistema modular.
            </p>
            <div className="flex flex-wrap justify-center gap-4 mb-12">
              <Button size="lg" className="bg-cyan-600 hover:bg-cyan-700">
                <Terminal className="w-5 h-5 mr-2" />
                Acceder al CLI
              </Button>
              <Button variant="outline" size="lg" className="border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black">
                <Globe className="w-5 h-5 mr-2" />
                Ver Documentación
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Modules Grid */}
      <section className="py-16">
        <div className="container mx-auto px-4">
          <h3 className="text-3xl font-bold text-center mb-12 text-cyan-400">
            Módulos Disponibles
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {modules.map((module, index) => (
              <Card key={index} className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all duration-300 hover:shadow-lg hover:shadow-cyan-400/20">
                <CardHeader>
                  <div className={`w-16 h-16 ${module.color} rounded-lg flex items-center justify-center mb-4 text-white`}>
                    {module.icon}
                  </div>
                  <CardTitle className="text-cyan-400">{module.title}</CardTitle>
                  <CardDescription className="text-gray-300">
                    {module.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Button variant="outline" className="w-full border-gray-600 text-gray-300 hover:bg-gray-700">
                    Explorar Módulo
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 bg-gray-900/50">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h3 className="text-3xl font-bold mb-6 text-cyan-400">
                Características Principales
              </h3>
              <ul className="space-y-4 text-gray-300">
                <li className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                  <span>50+ scripts de ciberseguridad especializados</span>
                </li>
                <li className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                  <span>CLI interactiva con navegación por módulos</span>
                </li>
                <li className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                  <span>Panel web con terminal integrada</span>
                </li>
                <li className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                  <span>Entornos Docker para práctica segura</span>
                </li>
                <li className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                  <span>Modo educativo con guías y tutoriales</span>
                </li>
                <li className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                  <span>API REST para integración con otras herramientas</span>
                </li>
              </ul>
            </div>
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h4 className="text-xl font-semibold mb-4 text-cyan-400">Instalación Rápida</h4>
              <div className="bg-black rounded p-4 font-mono text-sm text-green-400">
                <p>git clone https://github.com/descambiado/BOFA</p>
                <p>cd BOFA</p>
                <p>chmod +x bofa.sh</p>
                <p>./bofa.sh</p>
              </div>
              <p className="text-gray-400 mt-4 text-sm">
                O utiliza Docker para un despliegue completo:
              </p>
              <div className="bg-black rounded p-4 font-mono text-sm text-green-400 mt-2">
                <p>docker-compose up --build</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-700 bg-black/50 backdrop-blur-sm py-8">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div>
              <h5 className="font-semibold mb-3 text-cyan-400">BOFA</h5>
              <p className="text-gray-400 text-sm">
                Suite profesional de ciberseguridad ofensiva y defensiva.
                Desarrollada para pentesters, consultores IT y estudiantes.
              </p>
            </div>
            <div>
              <h5 className="font-semibold mb-3 text-cyan-400">Desarrollador</h5>
              <div className="text-gray-400 text-sm space-y-1">
                <p>@descambiado</p>
                <p>David Hernández Jiménez</p>
                <p>Administración de Sistemas Informáticos en Red</p>
                <p>Ciberseguridad | Pentesting | Consultor IT/CIBERSEC</p>
              </div>
            </div>
            <div>
              <h5 className="font-semibold mb-3 text-cyan-400">Enlaces</h5>
              <div className="text-gray-400 text-sm space-y-1">
                <p>GitHub: https://github.com/descambiado</p>
                <p>Email: david@descambiado.com</p>
                <p>LinkedIn: https://linkedin.com/in/descambiado</p>
              </div>
            </div>
          </div>
          <div className="border-t border-gray-700 mt-8 pt-6 text-center">
            <p className="text-gray-400 text-sm">
              © 2025 BOFA - Best Of All. Desarrollado por @descambiado. 
              Para uso educativo y profesional autorizado.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
