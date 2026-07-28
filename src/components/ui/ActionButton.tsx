
import { Button } from "@/components/ui/button";
import { ReactNode } from "react";

interface ActionButtonProps {
  title: string;
  description: string;
  icon: ReactNode;
  className?: string;
  onClick?: () => void;
}

export const ActionButton = ({ 
  title, 
  description, 
  icon, 
  className = "",
  onClick
}: ActionButtonProps) => {
  return (
    <Button
      variant="default"
      size="lg"
      className={`flex flex-col items-center space-y-2 h-auto p-6 text-left ${className}`}
      onClick={onClick}
    >
      <div className="flex items-center space-x-2">
        {icon}
        <span className="font-medium">{title}</span>
      </div>
      <span className="text-sm text-gray-300">{description}</span>
    </Button>
  );
};
