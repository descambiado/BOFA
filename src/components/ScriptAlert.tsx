
import { Alert, AlertDescription } from "@/components/ui/alert";
import { AlertTriangle, Shield, Info } from "lucide-react";

interface Script {
  name: string;
  category: string;
  impact_level?: string;
  risk_level?: string;
}

interface ScriptAlertProps {
  script: Script;
}

export const ScriptAlert = ({ script }: ScriptAlertProps) => {
  const getAlertConfig = () => {
    if (script.category === "red") {
      return {
        icon: AlertTriangle,
        className: "border-red-500/50 bg-red-500/10 text-red-400",
        title: "⚠️ Herramienta Ofensiva",
        message: "Esta es una herramienta de Red Team. Úsala solo en entornos autorizados."
      };
    }
    
    if (script.risk_level === "HIGH") {
      return {
        icon: AlertTriangle,
        className: "border-orange-500/50 bg-orange-500/10 text-orange-400",
        title: "🔥 Alto Impacto",
        message: "Este script puede tener un impacto significativo en el sistema objetivo."
      };
    }

    if (script.category === "blue") {
      return {
        icon: Shield,
        className: "border-blue-500/50 bg-blue-500/10 text-blue-400",
        title: "🛡️ Herramienta Defensiva",
        message: "Script de análisis y defensa. Seguro para uso en producción."
      };
    }

    return {
      icon: Info,
      className: "border-cyan-500/50 bg-cyan-500/10 text-cyan-400",
      title: "ℹ️ Información",
      message: "Revisa los parámetros antes de ejecutar."
    };
  };

  const config = getAlertConfig();
  const IconComponent = config.icon;

  return (
    <Alert className={config.className}>
      <IconComponent className="h-4 w-4" />
      <AlertDescription>
        <strong>{config.title}</strong><br />
        {config.message}
      </AlertDescription>
    </Alert>
  );
};
