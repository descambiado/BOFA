
import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { BookOpen, Play, CheckCircle, Clock, Trophy, ArrowLeft } from "lucide-react";
import { StudyLesson } from "@/components/StudyLesson";

interface LessonMetadata {
  id: string;
  title: string;
  description: string;
  category: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  estimated_time: string;
  prerequisites: string[];
  tags: string[];
  author: string;
  script: string;
  points: number;
}

interface StudyProgress {
  [lessonId: string]: {
    status: "new" | "in_progress" | "completed";
    score?: number;
    completedAt?: string;
  };
}

const Study = () => {
  const [selectedLesson, setSelectedLesson] = useState<LessonMetadata | null>(null);
  const [lessons, setLessons] = useState<LessonMetadata[]>([]);
  const [progress, setProgress] = useState<StudyProgress>({});
  const [totalPoints, setTotalPoints] = useState(0);

  useEffect(() => {
    // Simular carga de lecciones y progreso
    const mockLessons: LessonMetadata[] = [
      {
        id: "sql_injection",
        title: "SQL Injection Fundamentals",
        description: "Aprende a identificar y explotar vulnerabilidades de inyección SQL",
        category: "web",
        difficulty: "beginner",
        estimated_time: "30 minutos",
        prerequisites: [],
        tags: ["sql", "injection", "web", "owasp"],
        author: "@descambiado",
        script: "learn_sql_injection.py",
        points: 100
      },
      {
        id: "xss",
        title: "Cross-Site Scripting (XSS)",
        description: "Comprende y practica la explotación de vulnerabilidades XSS",
        category: "web",
        difficulty: "beginner",
        estimated_time: "25 minutos",
        prerequisites: ["sql_injection"],
        tags: ["xss", "javascript", "web", "owasp"],
        author: "@descambiado",
        script: "xss_trainer.py",
        points: 80
      },
      {
        id: "malware_basics",
        title: "Análisis de Malware Básico",
        description: "Introducción al análisis estático y dinámico de malware",
        category: "malware",
        difficulty: "intermediate",
        estimated_time: "45 minutos",
        prerequisites: [],
        tags: ["malware", "analysis", "reverse-engineering"],
        author: "@descambiado",
        script: "malware_basics.py",
        points: 120
      },
      {
        id: "network_layers",
        title: "Modelo de Capas de Red",
        description: "Comprende las capas OSI y TCP/IP para pentesting",
        category: "network",
        difficulty: "beginner",
        estimated_time: "20 minutos",
        prerequisites: [],
        tags: ["network", "osi", "tcp", "protocols"],
        author: "@descambiado",
        script: "network_layers_tutorial.py",
        points: 60
      }
    ];

    const mockProgress: StudyProgress = {
      sql_injection: { status: "completed", score: 95, completedAt: "2025-01-15" },
      xss: { status: "in_progress" },
      malware_basics: { status: "new" },
      network_layers: { status: "new" }
    };

    setLessons(mockLessons);
    setProgress(mockProgress);
    
    // Calcular puntos totales
    const points = Object.entries(mockProgress).reduce((total, [lessonId, prog]) => {
      if (prog.status === "completed") {
        const lesson = mockLessons.find(l => l.id === lessonId);
        return total + (lesson?.points || 0);
      }
      return total;
    }, 0);
    setTotalPoints(points);
  }, []);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "beginner": return "bg-green-500";
      case "intermediate": return "bg-yellow-500";
      case "advanced": return "bg-red-500";
      default: return "bg-gray-500";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed": return <CheckCircle className="w-5 h-5 text-green-400" />;
      case "in_progress": return <Clock className="w-5 h-5 text-yellow-400" />;
      default: return <BookOpen className="w-5 h-5 text-gray-400" />;
    }
  };

  const getCategoryIcon = (category: string) => {
    const iconMap: { [key: string]: string } = {
      web: "🌐",
      malware: "🦠",
      network: "📡",
      osint: "🔍",
      blue: "🛡️"
    };
    return iconMap[category] || "📚";
  };

  if (selectedLesson) {
    return (
      <StudyLesson 
        lesson={selectedLesson}
        progress={progress[selectedLesson.id]}
        onBack={() => setSelectedLesson(null)}
        onComplete={(score) => {
          setProgress(prev => ({
            ...prev,
            [selectedLesson.id]: {
              status: "completed",
              score,
              completedAt: new Date().toISOString().split('T')[0]
            }
          }));
          setTotalPoints(prev => prev + selectedLesson.points);
        }}
      />
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-cyan-400 mb-2">🎓 Modo Estudio</h1>
              <p className="text-gray-300">Aprende ciberseguridad con lecciones interactivas y retos</p>
            </div>
            <div className="text-right">
              <div className="flex items-center space-x-2 mb-2">
                <Trophy className="w-6 h-6 text-yellow-400" />
                <span className="text-2xl font-bold text-yellow-400">{totalPoints}</span>
                <span className="text-gray-400">puntos</span>
              </div>
              <p className="text-sm text-gray-400">
                {Object.values(progress).filter(p => p.status === "completed").length} de {lessons.length} completadas
              </p>
            </div>
          </div>
        </div>

        {/* Categories */}
        <div className="mb-8">
          <h2 className="text-xl font-semibold text-cyan-400 mb-4">Categorías</h2>
          <div className="flex flex-wrap gap-3">
            {Array.from(new Set(lessons.map(l => l.category))).map(category => (
              <Badge key={category} variant="outline" className="border-cyan-400 text-cyan-400">
                {getCategoryIcon(category)} {category.charAt(0).toUpperCase() + category.slice(1)}
              </Badge>
            ))}
          </div>
        </div>

        {/* Lessons Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {lessons.map((lesson) => {
            const lessonProgress = progress[lesson.id] || { status: "new" };
            
            return (
              <Card 
                key={lesson.id} 
                className="bg-gray-800/50 border-gray-700 hover:border-cyan-400 transition-all cursor-pointer"
                onClick={() => setSelectedLesson(lesson)}
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-2 mb-2">
                      {getStatusIcon(lessonProgress.status)}
                      <span className="text-2xl">{getCategoryIcon(lesson.category)}</span>
                    </div>
                    <Badge className={`${getDifficultyColor(lesson.difficulty)} text-white`}>
                      {lesson.difficulty}
                    </Badge>
                  </div>
                  <CardTitle className="text-cyan-400">{lesson.title}</CardTitle>
                  <CardDescription className="text-gray-300">
                    {lesson.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-sm text-gray-400">
                      <span>⏱️ {lesson.estimated_time}</span>
                      <span>🏆 {lesson.points} pts</span>
                    </div>
                    
                    {lesson.prerequisites.length > 0 && (
                      <div className="text-sm text-gray-400">
                        <span>Prerequisitos: </span>
                        {lesson.prerequisites.map(prereq => {
                          const isCompleted = progress[prereq]?.status === "completed";
                          return (
                            <span 
                              key={prereq} 
                              className={isCompleted ? "text-green-400" : "text-red-400"}
                            >
                              {prereq}
                            </span>
                          );
                        })}
                      </div>
                    )}

                    <div className="flex flex-wrap gap-1">
                      {lesson.tags.slice(0, 3).map(tag => (
                        <Badge key={tag} variant="secondary" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>

                    <Button 
                      className="w-full bg-cyan-600 hover:bg-cyan-700"
                      disabled={lesson.prerequisites.some(prereq => progress[prereq]?.status !== "completed")}
                    >
                      <Play className="w-4 h-4 mr-2" />
                      {lessonProgress.status === "completed" ? "Repasar" : "Comenzar"}
                    </Button>

                    {lessonProgress.status === "completed" && lessonProgress.score && (
                      <div className="text-center">
                        <span className="text-sm text-green-400">
                          ✅ Completada - Puntuación: {lessonProgress.score}%
                        </span>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default Study;
