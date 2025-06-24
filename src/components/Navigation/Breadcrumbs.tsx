
import { useLocation } from "react-router-dom";
import { ChevronRight, Home } from "lucide-react";

export const Breadcrumbs = () => {
  const location = useLocation();
  const pathSegments = location.pathname.split('/').filter(Boolean);

  const getBreadcrumbLabel = (segment: string) => {
    const labels: { [key: string]: string } = {
      'scripts': 'Scripts',
      'study': 'Estudio', 
      'labs': 'Labs',
      'history': 'Historial'
    };
    return labels[segment] || segment.charAt(0).toUpperCase() + segment.slice(1);
  };

  if (location.pathname === '/') {
    return null;
  }

  return (
    <nav className="bg-gray-800/30 border-b border-gray-700/50">
      <div className="container mx-auto px-6 py-3">
        <div className="flex items-center space-x-2 text-sm">
          <Home className="w-4 h-4 text-gray-400" />
          <span className="text-gray-400">Dashboard</span>
          
          {pathSegments.map((segment, index) => (
            <div key={segment} className="flex items-center space-x-2">
              <ChevronRight className="w-4 h-4 text-gray-500" />
              <span 
                className={
                  index === pathSegments.length - 1 
                    ? "text-cyan-400 font-medium" 
                    : "text-gray-400"
                }
              >
                {getBreadcrumbLabel(segment)}
              </span>
            </div>
          ))}
        </div>
      </div>
    </nav>
  );
};
