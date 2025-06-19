
import { AlertTriangle, Shield, Zap, Smartphone, Info } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";

interface ScriptAlertProps {
  script: {
    name: string;
    category: string;
    impact_level?: string;
    educational_value?: number;
  };
}

export const ScriptAlert = ({ script }: ScriptAlertProps) => {
  const getAlertLevel = () => {
    if (script.category === "red" || script.impact_level === "HIGH") {
      return {
        icon: <AlertTriangle className="w-4 h-4" />,
        variant: "destructive" as const,
        title: "⚠️ Herramienta Ofensiva",
        description: "Esta herramienta es para uso educativo en entornos controlados. Asegúrate de tener autorización antes de ejecutarla."
      };
    }
    
    if (script.category === "blue") {
      return {
        icon: <Shield className="w-4 h-4" />,
        variant: "default" as const,
        title: "🛡️ Herramienta Defensiva",
        description: "Herramienta de análisis y monitoreo para fortalecer la seguridad."
      };
    }
    
    if (script.category === "purple") {
      return {
        icon: <Zap className="w-4 h-4" />,
        variant: "default" as const,
        title: "🟣 Ejercicio Purple Team",
        description: "Simulación coordinada para validar defensas y entrenar equipos."
      };
    }
    
    if (script.category === "mobile") {
      return {
        icon: <Smartphone className="w-4 h-4" />,
        variant: "default" as const,
        title: "📱 Herramienta Móvil",
        description: "Compatible con dispositivos móviles y entornos Termux."
      };
    }
    
    return {
      icon: <Info className="w-4 h-4" />,
      variant: "default" as const,
      title: "📚 Herramienta Educativa",
      description: "Herramienta de aprendizaje y práctica de ciberseguridad."
    };
  };
  
  const getScriptBadges = () => {
    const badges = [];
    
    if (script.educational_value === 5) {
      badges.push({ text: "EDUCATIVO", color: "bg-blue-500" });
    }
    
    if (script.impact_level === "HIGH") {
      badges.push({ text: "ALTO RIESGO", color: "bg-red-500" });
    } else if (script.impact_level === "MEDIUM") {
      badges.push({ text: "RIESGO MEDIO", color: "bg-yellow-500" });
    } else {
      badges.push({ text: "BAJO RIESGO", color: "bg-green-500" });
    }
    
    if (script.category === "red") {
      badges.push({ text: "OFENSIVO", color: "bg-red-600" });
    } else if (script.category === "blue") {
      badges.push({ text: "DEFENSIVO", color: "bg-blue-600" });
    } else if (script.category === "purple") {
      badges.push({ text: "PURPLE TEAM", color: "bg-purple-600" });
    } else if (script.category === "mobile") {
      badges.push({ text: "MOBILE", color: "bg-orange-600" });
    }
    
    return badges;
  };

  const alert = getAlertLevel();
  const badges = getScriptBadges();

  return (
    <div className="space-y-3">
      <Alert variant={alert.variant}>
        {alert.icon}
        <AlertTitle>{alert.title}</AlertTitle>
        <AlertDescription>{alert.description}</AlertDescription>
      </Alert>
      
      <div className="flex flex-wrap gap-2">
        {badges.map((badge, index) => (
          <Badge key={index} className={`${badge.color} text-white text-xs`}>
            {badge.text}
          </Badge>
        ))}
      </div>
    </div>
  );
};
