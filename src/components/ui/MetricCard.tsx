
import { Card, CardContent } from "@/components/ui/card";
import { ReactNode } from "react";
import { TrendingUp, TrendingDown } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string;
  change: string;
  trend: "up" | "down";
  icon: ReactNode;
}

export const MetricCard = ({ title, value, change, trend, icon }: MetricCardProps) => {
  return (
    <Card className="bofa-card-dark border-primary/20 hover-glow hover-lift group">
      <CardContent className="p-6">
        <div className="flex items-center justify-between mb-3">
          <div className="text-primary group-hover:scale-110 transition-transform duration-200">
            {icon}
          </div>
          <div className={`flex items-center space-x-1 text-sm font-semibold ${
            trend === 'up' ? 'text-success' : 'text-destructive'
          }`}>
            {trend === 'up' ? <TrendingUp className="w-4 h-4" /> : <TrendingDown className="w-4 h-4" />}
            <span>{change}</span>
          </div>
        </div>
        <div className="space-y-2">
          <h3 className="text-3xl font-bold text-foreground group-hover:text-primary transition-colors duration-200">
            {value}
          </h3>
          <p className="text-muted-foreground text-sm font-medium">{title}</p>
        </div>
      </CardContent>
    </Card>
  );
};
