
import React, { useState } from 'react';
import { Shield, Terminal, Globe, Lock, Eye, Wrench, PlayCircle, Square, RefreshCw, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";

interface Lab {
  id: string;
  name: string;
  description: string;
  category: string;
  difficulty: string;
  ports: string[];
  services: string[];
  status: 'stopped' | 'starting' | 'running' | 'stopping';
  icon: React.ReactNode;
}

const Labs = () => {
  const { toast } = useToast();
  const [labs, setLabs] = useState<Lab[]>([
    {
      id: 'web-sqli',
      name: 'SQL Injection Lab',
      description: 'Vulnerable web application for practicing SQL injection attacks',
      category: 'web',
      difficulty: 'beginner',
      ports: ['80', '3306'],
      services: ['Apache', 'MySQL', 'PHP'],
      status: 'stopped',
      icon: <Globe className="w-6 h-6" />
    },
    {
      id: 'internal-network',
      name: 'Internal Network Lab',
      description: 'Multi-machine network for lateral movement and privilege escalation',
      category: 'red',
      difficulty: 'intermediate',
      ports: ['22', '80', '445', '139'],
      services: ['SSH', 'SMB', 'HTTP', 'FTP'],
      status: 'stopped',
      icon: <Terminal className="w-6 h-6" />
    },
    {
      id: 'siem-detection',
      name: 'SIEM Detection Lab',
      description: 'Blue team lab with Wazuh SIEM for log analysis and threat detection',
      category: 'blue',
      difficulty: 'advanced',
      ports: ['443', '1514', '1515'],
      services: ['Wazuh', 'Elasticsearch', 'Kibana'],
      status: 'stopped',
      icon: <Shield className="w-6 h-6" />
    },
    {
      id: 'malware-lab',
      name: 'Malware Analysis Lab',
      description: 'Isolated environment for safe malware analysis and reverse engineering',
      category: 'malware',
      difficulty: 'advanced',
      ports: ['8080', '8443'],
      services: ['REMnux', 'FLARE VM', 'Cuckoo'],
      status: 'stopped',
      icon: <Lock className="w-6 h-6" />
    },
    {
      id: 'red-vs-blue',
      name: 'Red vs Blue Exercise',
      description: 'Competitive environment for red team vs blue team exercises',
      category: 'exercise',
      difficulty: 'expert',
      ports: ['80', '443', '22', '3389'],
      services: ['Windows AD', 'Linux', 'Web Apps', 'SIEM'],
      status: 'stopped',
      icon: <Eye className="w-6 h-6" />
    }
  ]);

  const categories = [
    { id: 'all', name: 'Todos', icon: <Wrench className="w-4 h-4" /> },
    { id: 'web', name: 'Web', icon: <Globe className="w-4 h-4" /> },
    { id: 'red', name: 'Red Team', icon: <Terminal className="w-4 h-4" /> },
    { id: 'blue', name: 'Blue Team', icon: <Shield className="w-4 h-4" /> },
    { id: 'malware', name: 'Malware', icon: <Lock className="w-4 h-4" /> },
    { id: 'exercise', name: 'Ejercicios', icon: <Eye className="w-4 h-4" /> }
  ];

  const [selectedCategory, setSelectedCategory] = useState('all');

  const filteredLabs = selectedCategory === 'all' 
    ? labs 
    : labs.filter(lab => lab.category === selectedCategory);

  const handleLabAction = async (labId: string, action: 'start' | 'stop' | 'reset' | 'access') => {
    const lab = labs.find(l => l.id === labId);
    if (!lab) return;

    if (action === 'access' && lab.status !== 'running') {
      toast({
        title: "Error",
        description: "El laboratorio debe estar ejecutándose para acceder",
        variant: "destructive"
      });
      return;
    }

    setLabs(prev => prev.map(l => 
      l.id === labId 
        ? { ...l, status: action === 'start' ? 'starting' : action === 'stop' ? 'stopping' : l.status }
        : l
    ));

    try {
      const response = await fetch(`http://localhost:8000/api/labs/${labId}/${action}`, {
        method: 'POST'
      });

      if (response.ok) {
        const newStatus = action === 'start' ? 'running' : 'stopped';
        setLabs(prev => prev.map(l => 
          l.id === labId ? { ...l, status: newStatus } : l
        ));

        if (action === 'access') {
          window.open(`http://localhost:${lab.ports[0]}`, '_blank');
        }

        toast({
          title: "Éxito",
          description: `Laboratorio ${lab.name} ${
            action === 'start' ? 'iniciado' : 
            action === 'stop' ? 'detenido' : 
            action === 'reset' ? 'reiniciado' : 
            'accedido'
          } correctamente`
        });
      } else {
        throw new Error('Error en la operación');
      }
    } catch (error) {
      setLabs(prev => prev.map(l => 
        l.id === labId ? { ...l, status: 'stopped' } : l
      ));
      
      toast({
        title: "Error",
        description: `No se pudo ${action} el laboratorio ${lab.name}`,
        variant: "destructive"
      });
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'bg-green-500';
      case 'intermediate': return 'bg-yellow-500';
      case 'advanced': return 'bg-orange-500';
      case 'expert': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'bg-green-500';
      case 'starting': case 'stopping': return 'bg-yellow-500';
      case 'stopped': return 'bg-gray-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white">
      {/* Header */}
      <header className="border-b border-gray-700 bg-black/50 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Wrench className="w-10 h-10 text-cyan-400" />
              <div>
                <h1 className="text-2xl font-bold text-cyan-400">Laboratorios Docker</h1>
                <p className="text-sm text-gray-400">Entornos vulnerables para práctica</p>
              </div>
            </div>
            <Button 
              onClick={() => window.history.back()}
              variant="outline" 
              className="border-cyan-400 text-cyan-400"
            >
              ← Volver
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-8">
        {/* Category Tabs */}
        <Tabs value={selectedCategory} onValueChange={setSelectedCategory} className="mb-8">
          <TabsList className="grid grid-cols-6 w-full bg-gray-800">
            {categories.map((category) => (
              <TabsTrigger 
                key={category.id} 
                value={category.id}
                className="flex items-center space-x-2 data-[state=active]:bg-cyan-600"
              >
                {category.icon}
                <span className="hidden sm:inline">{category.name}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>

        {/* Labs Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredLabs.map((lab) => (
            <Card key={lab.id} className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all duration-300">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="p-2 bg-cyan-600 rounded-lg">
                      {lab.icon}
                    </div>
                    <div>
                      <CardTitle className="text-cyan-400">{lab.name}</CardTitle>
                      <div className="flex items-center space-x-2 mt-1">
                        <Badge 
                          className={`${getDifficultyColor(lab.difficulty)} text-white text-xs`}
                        >
                          {lab.difficulty}
                        </Badge>
                        <Badge 
                          className={`${getStatusColor(lab.status)} text-white text-xs`}
                        >
                          {lab.status}
                        </Badge>
                      </div>
                    </div>
                  </div>
                </div>
                <CardDescription className="text-gray-300 mt-2">
                  {lab.description}
                </CardDescription>
              </CardHeader>
              
              <CardContent>
                <div className="space-y-4">
                  {/* Services */}
                  <div>
                    <p className="text-sm text-gray-400 mb-2">Servicios:</p>
                    <div className="flex flex-wrap gap-1">
                      {lab.services.map((service, index) => (
                        <Badge key={index} variant="outline" className="text-xs border-gray-600">
                          {service}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Ports */}
                  <div>
                    <p className="text-sm text-gray-400 mb-2">Puertos:</p>
                    <div className="flex flex-wrap gap-1">
                      {lab.ports.map((port, index) => (
                        <Badge key={index} variant="outline" className="text-xs border-gray-600">
                          {port}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-wrap gap-2 pt-4">
                    {lab.status === 'stopped' ? (
                      <Button 
                        size="sm" 
                        className="bg-green-600 hover:bg-green-700"
                        onClick={() => handleLabAction(lab.id, 'start')}
                      >
                        <PlayCircle className="w-4 h-4 mr-1" />
                        Iniciar
                      </Button>
                    ) : lab.status === 'running' ? (
                      <>
                        <Button 
                          size="sm" 
                          className="bg-blue-600 hover:bg-blue-700"
                          onClick={() => handleLabAction(lab.id, 'access')}
                        >
                          <ExternalLink className="w-4 h-4 mr-1" />
                          Acceder
                        </Button>
                        <Button 
                          size="sm" 
                          variant="outline"
                          className="border-red-600 text-red-400 hover:bg-red-600"
                          onClick={() => handleLabAction(lab.id, 'stop')}
                        >
                          <Square className="w-4 h-4 mr-1" />
                          Detener
                        </Button>
                      </>
                    ) : (
                      <Button size="sm" disabled>
                        <RefreshCw className="w-4 h-4 mr-1 animate-spin" />
                        {lab.status === 'starting' ? 'Iniciando...' : 'Deteniendo...'}
                      </Button>
                    )}
                    
                    <Button 
                      size="sm" 
                      variant="outline"
                      className="border-yellow-600 text-yellow-400 hover:bg-yellow-600"
                      onClick={() => handleLabAction(lab.id, 'reset')}
                    >
                      <RefreshCw className="w-4 h-4 mr-1" />
                      Reset
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {filteredLabs.length === 0 && (
          <div className="text-center py-12">
            <Wrench className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <h3 className="text-xl text-gray-400 mb-2">No hay laboratorios disponibles</h3>
            <p className="text-gray-500">Los laboratorios para esta categoría están en desarrollo</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Labs;
