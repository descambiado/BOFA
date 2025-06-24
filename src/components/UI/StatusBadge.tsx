
import { CheckCircle, XCircle, Clock, AlertTriangle, Square } from "lucide-react";

interface StatusBadgeProps {
  status: "success" | "error" | "warning" | "pending" | "running" | "stopped" | "starting";
  text?: string;
  showIcon?: boolean;
}

export const StatusBadge = ({ status, text, showIcon = true }: StatusBadgeProps) => {
  const getStatusConfig = () => {
    switch (status) {
      case "success":
        return {
          icon: CheckCircle,
          className: "bg-green-500/20 text-green-400 border-green-500/30",  
          text: text || "Éxito"
        };
      case "error":
        return {
          icon: XCircle,
          className: "bg-red-500/20 text-red-400 border-red-500/30",
          text: text || "Error"
        };
      case "warning":
        return {
          icon: AlertTriangle,
          className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
          text: text || "Advertencia"
        };
      case "pending":
        return {
          icon: Clock,
          className: "bg-blue-500/20 text-blue-400 border-blue-500/30",
          text: text || "Pendiente"
        };
      case "running":
        return {
          icon: Clock,
          className: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30 animate-pulse",
          text: text || "Ejecutando"
        };
      case "stopped":
        return {
          icon: Square,
          className: "bg-gray-500/20 text-gray-400 border-gray-500/30",
          text: text || "Detenido"
        };
      case "starting":
        return {
          icon: Clock,
          className: "bg-orange-500/20 text-orange-400 border-orange-500/30 animate-pulse",
          text: text || "Iniciando"
        };
      default:
        return {
          icon: Clock,
          className: "bg-gray-500/20 text-gray-400 border-gray-500/30",
          text: text || "Desconocido"
        };
    }
  };

  const config = getStatusConfig();
  const IconComponent = config.icon;

  return (
    <div className={`inline-flex items-center space-x-1 px-2 py-1 rounded-full border text-xs font-medium ${config.className}`}>
      {showIcon && <IconComponent className="w-3 h-3" />}
      <span>{config.text}</span>
    </div>
  );
};
