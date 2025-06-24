
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Home, ArrowLeft, Search } from "lucide-react";

const NotFound = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white flex items-center justify-center p-6">
      <Card className="bg-gray-800/50 border-gray-700 max-w-md w-full">
        <CardContent className="p-8 text-center space-y-6">
          <div className="space-y-4">
            <div className="text-6xl font-bold text-cyan-400">404</div>
            <h1 className="text-2xl font-bold text-white">Página No Encontrada</h1>
            <p className="text-gray-400">
              La página que buscas no existe o ha sido movida. 
              Verifica la URL o regresa al dashboard principal.
            </p>
          </div>

          <div className="space-y-3">
            <Link to="/" className="block">
              <Button className="w-full bg-cyan-600 hover:bg-cyan-700">
                <Home className="w-4 h-4 mr-2" />
                Ir al Dashboard
              </Button>
            </Link>
            
            <Button 
              variant="outline" 
              onClick={() => window.history.back()}
              className="w-full border-gray-600 text-gray-300 hover:bg-gray-700"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Volver Atrás
            </Button>
          </div>

          <div className="pt-4 border-t border-gray-700">
            <p className="text-sm text-gray-500 mb-3">Páginas disponibles:</p>
            <div className="flex flex-wrap gap-2 justify-center">
              <Link to="/scripts">
                <Button variant="ghost" size="sm" className="text-xs">Scripts</Button>
              </Link>
              <Link to="/study">
                <Button variant="ghost" size="sm" className="text-xs">Estudio</Button>
              </Link>
              <Link to="/labs">
                <Button variant="ghost" size="sm" className="text-xs">Labs</Button>
              </Link>
              <Link to="/history">
                <Button variant="ghost" size="sm" className="text-xs">Historial</Button>
              </Link>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default NotFound;
