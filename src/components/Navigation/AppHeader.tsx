import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Activity,
  BookOpen,
  Clock,
  Code,
  Crosshair,
  Eye,
  Fingerprint,
  Home,
  LogOut,
  Menu,
  Server,
  Shield,
  Terminal,
  User,
  Wifi,
  WifiOff,
  Workflow,
  X,
} from "lucide-react";
import { APP_CONFIG } from "@/config/app";
import { authService } from "@/services/api";

export const AppHeader = () => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [apiStatus, setApiStatus] = useState<"checking" | "online" | "offline">("checking");
  const location = useLocation();
  const currentUser = authService.getCurrentUser();

  const handleLogout = () => {
    authService.logout();
    window.location.reload();
  };

  useEffect(() => {
    const mockMode = APP_CONFIG.api.mockMode;
    if (mockMode === true) {
      setApiStatus("online");
      return;
    }

    const checkApiStatus = async () => {
      try {
        const response = await fetch(`${APP_CONFIG.api.baseUrl}/health`, {
          signal: AbortSignal.timeout(3000),
        });
        setApiStatus(response.ok ? "online" : "offline");
      } catch {
        setApiStatus("offline");
      }
    };

    void checkApiStatus();
    const interval = setInterval(checkApiStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const navigation = [
    { name: "Overview", href: "/dashboard", icon: Home },
    { name: "Salud", href: "/health", icon: Activity },
    { name: "Fabric", href: "/fabric", icon: Fingerprint },
    { name: "Scripts", href: "/scripts", icon: Terminal },
    { name: "Flows", href: "/flows", icon: Workflow },
    { name: "Bounty", href: "/bounty", icon: Crosshair },
    { name: "Biblioteca", href: "/library", icon: Code },
    { name: "Labs", href: "/labs", icon: Eye },
    { name: "Historial", href: "/history", icon: Clock },
    { name: "Estudiar", href: "/study", icon: BookOpen },
  ];

  const isActive = (path: string) => location.pathname === path;

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/90">
      <div className="container mx-auto flex h-16 items-center px-6">
        <Link to="/" className="flex items-center space-x-2">
          <Shield className="h-8 w-8 text-primary" />
          <div className="flex flex-col">
            <span className="text-lg font-bold text-foreground">{APP_CONFIG.name}</span>
            <span className="text-xs font-semibold text-primary">v{APP_CONFIG.version}</span>
          </div>
        </Link>

        <div className="ml-4">
          <Badge className="border border-cyan-400/20 bg-cyan-500/10 text-cyan-200 text-xs">
            {APP_CONFIG.codename}
          </Badge>
        </div>

        <nav className="ml-6 hidden items-center space-x-1 lg:flex">
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.name}
                to={item.href}
                title={item.name}
                className={`flex items-center space-x-2 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  isActive(item.href)
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden 2xl:inline">{item.name}</span>
              </Link>
            );
          })}
        </nav>

        <div className="flex-1" />

        <div className="hidden items-center space-x-4 xl:flex">
          {currentUser ? (
            <div className="flex items-center space-x-2">
              <User className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium text-foreground">{currentUser.fullName}</span>
              <Badge className="bg-secondary text-secondary-foreground text-xs">{currentUser.role.toUpperCase()}</Badge>
            </div>
          ) : null}

          <div className="flex items-center space-x-2 text-sm">
            {apiStatus === "online" ? (
              <>
                <div className="h-2 w-2 rounded-full bg-success animate-pulse" />
                <Wifi className="h-4 w-4 text-success" />
                <span className="font-medium text-success">Runtime online</span>
              </>
            ) : apiStatus === "offline" ? (
              <>
                <div className="h-2 w-2 rounded-full bg-destructive animate-pulse" />
                <WifiOff className="h-4 w-4 text-destructive" />
                <span className="font-medium text-destructive">Runtime offline</span>
              </>
            ) : (
              <>
                <div className="h-2 w-2 rounded-full bg-warning animate-pulse" />
                <Server className="h-4 w-4 text-warning" />
                <span className="font-medium text-warning">Conectando</span>
              </>
            )}
          </div>

          {currentUser ? (
            <Button
              variant="ghost"
              size="sm"
              className="text-muted-foreground hover:bg-muted hover:text-destructive"
              onClick={handleLogout}
              title="Cerrar sesion"
            >
              <LogOut className="h-4 w-4" />
            </Button>
          ) : null}
        </div>

        <Button
          variant="ghost"
          size="sm"
          className="ml-4 lg:hidden"
          onClick={() => setIsMobileMenuOpen((current) => !current)}
        >
          {isMobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </Button>
      </div>

      {isMobileMenuOpen ? (
        <div className="border-t border-border bg-background lg:hidden">
          <nav className="space-y-2 px-6 py-4">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center space-x-2 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                    isActive(item.href)
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  }`}
                  onClick={() => setIsMobileMenuOpen(false)}
                >
                  <Icon className="h-4 w-4" />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>
        </div>
      ) : null}
    </header>
  );
};
