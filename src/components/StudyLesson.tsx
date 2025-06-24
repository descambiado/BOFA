
import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Play, CheckCircle, Trophy, Clock } from "lucide-react";
import { toast } from "sonner";

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

interface LessonProgress {
  status: "new" | "in_progress" | "completed";
  score?: number;
  completedAt?: string;
}

interface StudyLessonProps {
  lesson: LessonMetadata;
  progress: LessonProgress;
  onBack: () => void;
  onComplete: (score: number) => void;
}

export const StudyLesson = ({ lesson, progress, onBack, onComplete }: StudyLessonProps) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [isRunning, setIsRunning] = useState(false);
  const [lessonProgress, setLessonProgress] = useState(0);
  const [answers, setAnswers] = useState<{ [key: number]: string }>({});

  // Simulated lesson content
  const lessonSteps = [
    {
      type: "theory",
      title: "Introducción",
      content: `Bienvenido a ${lesson.title}. En esta lección aprenderás sobre ${lesson.description.toLowerCase()}.`,
    },
    {
      type: "practical",
      title: "Ejercicio Práctico",
      content: "Vamos a ejecutar el script para ver cómo funciona en la práctica.",
    },
    {
      type: "quiz",
      title: "Evaluación",
      content: "Responde las siguientes preguntas para completar la lección.",
      questions: [
        {
          question: `¿Cuál es el objetivo principal de ${lesson.title}?`,
          options: ["Opción A", "Opción B", "Opción C"],
          correct: 1
        }
      ]
    }
  ];

  useEffect(() => {
    const progress = ((currentStep + 1) / lessonSteps.length) * 100;
    setLessonProgress(progress);
  }, [currentStep]);

  const handleNext = () => {
    if (currentStep < lessonSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      // Lesson completed
      const score = Math.floor(Math.random() * 30) + 70; // 70-100%
      onComplete(score);
      toast.success(`¡Lección completada! Puntuación: ${score}%`);
    }
  };

  const handlePractical = () => {
    setIsRunning(true);
    // Simulate script execution
    setTimeout(() => {
      setIsRunning(false);
      toast.success("Ejercicio completado exitosamente");
      handleNext();
    }, 2000);
  };

  const currentStepData = lessonSteps[currentStep];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-6">
      <div className="container mx-auto max-w-4xl">
        {/* Header */}
        <div className="mb-6">
          <Button 
            variant="outline" 
            onClick={onBack}
            className="border-gray-600 text-gray-300 hover:bg-gray-700 mb-4"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Volver al Estudio
          </Button>
          
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-cyan-400 mb-2">{lesson.title}</h1>
              <div className="flex items-center space-x-4">
                <Badge className="bg-green-600">{lesson.difficulty}</Badge>
                <div className="flex items-center space-x-1 text-gray-400">
                  <Clock className="w-4 h-4" />
                  <span>{lesson.estimated_time}</span>
                </div>
                <div className="flex items-center space-x-1 text-yellow-400">
                  <Trophy className="w-4 h-4" />
                  <span>{lesson.points} pts</span>
                </div>
              </div>
            </div>
            
            {progress.status === "completed" && (
              <div className="text-right">
                <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                <p className="text-green-400 text-sm">Completada</p>
                {progress.score && (
                  <p className="text-green-400 text-sm">Puntuación: {progress.score}%</p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Progress */}
        <Card className="bg-gray-800/50 border-gray-700 mb-6">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Progreso de la Lección</span>
              <span className="text-sm text-cyan-400">{Math.round(lessonProgress)}%</span>
            </div>
            <Progress value={lessonProgress} className="h-2" />
            <div className="flex justify-between mt-2 text-xs text-gray-500">
              <span>Paso {currentStep + 1} de {lessonSteps.length}</span>
              <span>{currentStepData.title}</span>
            </div>
          </CardContent>
        </Card>

        {/* Lesson Content */}
        <Card className="bg-gray-800/50 border-gray-700">
          <CardHeader>
            <CardTitle className="text-cyan-400">{currentStepData.title}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="text-gray-300">
              {currentStepData.content}
            </div>

            {currentStepData.type === "theory" && (
              <div className="bg-gray-900/50 p-4 rounded-lg">
                <h4 className="text-cyan-400 mb-2">Conceptos Clave:</h4>
                <ul className="list-disc list-inside space-y-1 text-gray-300">
                  <li>Fundamentos de {lesson.title}</li>
                  <li>Aplicaciones prácticas en ciberseguridad</li>
                  <li>Mejores prácticas y consideraciones éticas</li>
                </ul>
              </div>
            )}

            {currentStepData.type === "practical" && (
              <div className="bg-black p-4 rounded-lg">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-cyan-400">Consola de Práctica</h4>
                  <Button 
                    onClick={handlePractical}
                    disabled={isRunning}
                    className="bg-green-600 hover:bg-green-700"
                  >
                    <Play className="w-4 h-4 mr-2" />
                    {isRunning ? "Ejecutando..." : "Ejecutar Ejercicio"}
                  </Button>
                </div>
                <div className="font-mono text-sm text-green-400">
                  {isRunning ? (
                    <div className="animate-pulse">
                      [INFO] Ejecutando {lesson.script}...<br />
                      [INFO] Procesando datos...<br />
                      [SUCCESS] Ejercicio completado exitosamente
                    </div>
                  ) : (
                    <div className="text-gray-500">
                      Presiona "Ejecutar Ejercicio" para comenzar la práctica...
                    </div>
                  )}
                </div>
              </div>
            )}

            {currentStepData.type === "quiz" && currentStepData.questions && (
              <div className="space-y-4">
                {currentStepData.questions.map((q, index) => (
                  <div key={index} className="bg-gray-900/50 p-4 rounded-lg">
                    <h4 className="text-cyan-400 mb-3">{q.question}</h4>
                    <div className="space-y-2">
                      {q.options.map((option, optIndex) => (
                        <label key={optIndex} className="flex items-center space-x-2 cursor-pointer">
                          <input
                            type="radio"
                            name={`question-${index}`}
                            value={optIndex}
                            onChange={(e) => setAnswers({...answers, [index]: e.target.value})}
                            className="text-cyan-400"
                          />
                          <span className="text-gray-300">{option}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex justify-between">
              <Button 
                variant="outline"
                onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
                disabled={currentStep === 0}
                className="border-gray-600 text-gray-300 hover:bg-gray-700"
              >
                Anterior
              </Button>
              
              <Button 
                onClick={currentStepData.type === "practical" ? handlePractical : handleNext}
                disabled={isRunning}
                className="bg-cyan-600 hover:bg-cyan-700"
              >
                {currentStep === lessonSteps.length - 1 ? "Completar Lección" : "Siguiente"}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
