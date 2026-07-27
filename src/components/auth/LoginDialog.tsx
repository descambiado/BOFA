import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Shield, Lock, User } from "lucide-react";
import { authService } from "@/services/api";
import { APP_CONFIG } from "@/config/app";

interface LoginDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

export const LoginDialog = ({ open, onOpenChange, onSuccess }: LoginDialogProps) => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin123');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      await authService.login(username, password);
      onOpenChange(false);
      onSuccess?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error de autenticación');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader className="space-y-3">
          <div className="flex items-center justify-center space-x-2">
            <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-purple-500 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <DialogTitle className="text-xl font-bold">
                {APP_CONFIG.name} v{APP_CONFIG.version}
              </DialogTitle>
              <p className="text-sm text-muted-foreground">
                {APP_CONFIG.codename}
              </p>
            </div>
          </div>
          <DialogDescription className="text-center">
            Inicie sesión para acceder a la suite de ciberseguridad
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="username" className="flex items-center space-x-2">
              <User className="w-4 h-4" />
              <span>Usuario</span>
            </Label>
            <Input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Ingrese su usuario"
              required
              disabled={isLoading}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="password" className="flex items-center space-x-2">
              <Lock className="w-4 h-4" />
              <span>Contraseña</span>
            </Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Ingrese su contraseña"
              required
              disabled={isLoading}
            />
          </div>

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="bg-muted/50 p-3 rounded-lg text-sm space-y-2">
            <p className="font-medium text-muted-foreground mb-2">👤 Usuarios disponibles:</p>
            <div className="space-y-1">
              <p className="text-xs"><strong>Admin:</strong> admin / admin123</p>
              <p className="text-xs"><strong>Red Team:</strong> redteam / red123</p>
              <p className="text-xs"><strong>Blue Team:</strong> blueteam / blue123</p>
            </div>
            <p className="text-xs text-muted-foreground/70 mt-2">
              ✨ Sistema de autenticación JWT completamente funcional
            </p>
          </div>

          <Button
            type="submit"
            className="w-full"
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Iniciando sesión...
              </>
            ) : (
              'Iniciar Sesión'
            )}
          </Button>
        </form>

        <div className="text-center text-xs text-muted-foreground">
          <p>Desarrollado por {APP_CONFIG.developer.name}</p>
          <p>{APP_CONFIG.developer.email}</p>
        </div>
      </DialogContent>
    </Dialog>
  );
};