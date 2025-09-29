
import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  NavigationMenu,
  NavigationMenuContent,
  NavigationMenuItem,
  NavigationMenuLink,
  NavigationMenuList,
  NavigationMenuTrigger,
} from "@/components/ui/navigation-menu";
import { 
  Shield, 
  Terminal, 
  Eye, 
  Clock, 
  BookOpen, 
  Menu, 
  X,
  Home,
  Zap,
  Wifi,
  WifiOff,
  Server,
  User,
  LogOut,
  Code
} from "lucide-react";
import { APP_CONFIG } from "@/config/app";
import { authService } from "@/services/api";
import { toast } from "sonner";

export const AppHeader = () => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [apiStatus, setApiStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  const location = useLocation();
  const currentUser = authService.getCurrentUser();

  const handleLogout = () => {
    authService.logout();
    window.location.reload();
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return 'bg-purple-500';
      case 'red_team': return 'bg-red-500';
      case 'blue_team': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  useEffect(() => {
    const mockMode: any = APP_CONFIG.api.mockMode;
    // Si mockMode === true forzamos online; con 'auto' o false, verificamos /health
    if (mockMode === true) {
      setApiStatus('online');
      return;
    }
    
    const checkApiStatus = async () => {
      try {
        const response = await fetch(`${APP_CONFIG.api.baseUrl}/health`, {
          signal: AbortSignal.timeout(3000)
        });
        setApiStatus(response.ok ? 'online' : 'offline');
      } catch (error) {
        setApiStatus('offline');
      }
    };

    checkApiStatus();
    const interval = setInterval(checkApiStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const navigation = [
    { name: "Dashboard", href: "/dashboard", icon: Home },
    { name: "Scripts", href: "/scripts", icon: Terminal },
    { name: "Biblioteca", href: "/library", icon: Code },
    { name: "Labs", href: "/labs", icon: Eye },
    { name: "Historial", href: "/history", icon: Clock },
    { name: "Estudiar", href: "/study", icon: BookOpen },
  ];

  const isActive = (path: string) => location.pathname === path;

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/90">
      <div className="container mx-auto flex h-16 items-center px-6">
        {/* Logo */}
        <Link to="/" className="flex items-center space-x-2">
          <div className="flex items-center space-x-2">
            <Shield className="w-8 h-8 text-primary" />
            <div className="flex flex-col">
              <span className="font-bold text-foreground text-lg">{APP_CONFIG.name}</span>
              <span className="text-xs text-primary font-semibold">v{APP_CONFIG.version}</span>
            </div>
          </div>
        </Link>

        {/* Versión Badge */}
        <div className="ml-4">
          <Badge className="bg-primary text-primary-foreground text-xs">
            <Zap className="w-3 h-3 mr-1" />
            {APP_CONFIG.codename.toUpperCase()}
          </Badge>
        </div>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center space-x-1 ml-8">
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.name}
                to={item.href}
                className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive(item.href)
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted"
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* Spacer */}
        <div className="flex-1" />

        {/* User Info & Actions */}
        <div className="hidden md:flex items-center space-x-4">
          {/* User Info */}
          {currentUser && (
            <div className="flex items-center space-x-2">
              <User className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-medium text-foreground">{currentUser.fullName}</span>
              <Badge className="text-xs bg-secondary text-secondary-foreground">
                {currentUser.role.toUpperCase()}
              </Badge>
            </div>
          )}
          
          {/* API Status */}
          <div className="flex items-center space-x-2 text-sm">
            {apiStatus === 'online' ? (
              <>
                <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
                <Wifi className="w-4 h-4 text-success" />
                <span className="text-success font-medium">Sistema Online</span>
              </>
            ) : apiStatus === 'offline' ? (
              <>
                <div className="w-2 h-2 bg-destructive rounded-full animate-pulse"></div>
                <WifiOff className="w-4 h-4 text-destructive" />
                <span className="text-destructive font-medium">Sistema Offline</span>
              </>
            ) : (
              <>
                <div className="w-2 h-2 bg-warning rounded-full animate-pulse"></div>
                <Server className="w-4 h-4 text-warning" />
                <span className="text-warning font-medium">Conectando...</span>
              </>
            )}
          </div>
          
          {/* Logout Button */}
          {currentUser && (
            <Button 
              variant="ghost" 
              size="sm" 
              className="text-muted-foreground hover:text-destructive hover:bg-muted"
              onClick={handleLogout}
              title="Cerrar sesión"
            >
              <LogOut className="w-4 h-4" />
            </Button>
          )}
        </div>

        {/* Mobile menu button */}
        <Button
          variant="ghost"
          size="sm"
          className="md:hidden ml-4"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        >
          {isMobileMenuOpen ? (
            <X className="w-5 h-5" />
          ) : (
            <Menu className="w-5 h-5" />
          )}
        </Button>
      </div>

      {/* Mobile Navigation */}
      {isMobileMenuOpen && (
        <div className="md:hidden border-t border-border bg-background">
          <nav className="px-6 py-4 space-y-2">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActive(item.href)
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted"
                  }`}
                  onClick={() => setIsMobileMenuOpen(false)}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>
        </div>
      )}
    </header>
  );
};
