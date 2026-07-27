import { useEffect, useState } from "react";
import { Loader2, Lock, Mail, Shield, User } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { APP_CONFIG } from "@/config/app";
import { authService } from "@/services/api";

interface LoginDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

export const LoginDialog = ({ open, onOpenChange, onSuccess }: LoginDialogProps) => {
  const [mode, setMode] = useState<"login" | "bootstrap">("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    let active = true;
    authService
      .getBootstrapStatus()
      .then((required) => {
        if (active) setMode(required ? "bootstrap" : "login");
      })
      .catch(() => {
        if (active) setMode("login");
      });
    return () => {
      active = false;
    };
  }, [open]);

  const selectMode = (nextMode: "login" | "bootstrap") => {
    setMode(nextMode);
    setError("");
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      if (mode === "bootstrap") {
        await authService.registerInitialAdmin(username, email, password);
      }
      await authService.login(username, password);
      onOpenChange(false);
      onSuccess?.();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo completar la autenticacion");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="border-cyan-400/20 bg-slate-950 text-slate-100 sm:max-w-md">
        <DialogHeader className="space-y-3">
          <div className="flex items-center justify-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-400/15">
              <Shield className="h-6 w-6 text-cyan-300" />
            </div>
            <div>
              <DialogTitle className="text-xl font-bold">
                {APP_CONFIG.name} v{APP_CONFIG.version}
              </DialogTitle>
              <p className="text-sm text-slate-400">{APP_CONFIG.codename}</p>
            </div>
          </div>
          <DialogDescription className="text-center text-slate-400">
            Autenticacion contra el runtime local. BOFA no incluye credenciales ni sesiones simuladas.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-2 gap-2 rounded-xl bg-slate-900 p-1">
          <Button
            type="button"
            variant={mode === "login" ? "default" : "ghost"}
            onClick={() => selectMode("login")}
          >
            Iniciar sesion
          </Button>
          <Button
            type="button"
            variant={mode === "bootstrap" ? "default" : "ghost"}
            onClick={() => selectMode("bootstrap")}
          >
            Primer arranque
          </Button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="username" className="flex items-center gap-2">
              <User className="h-4 w-4" />
              Usuario
            </Label>
            <Input
              id="username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="descambiado"
              minLength={3}
              maxLength={64}
              required
              disabled={isLoading}
            />
          </div>

          {mode === "bootstrap" ? (
            <div className="space-y-2">
              <Label htmlFor="email" className="flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Email
              </Label>
              <Input
                id="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                required
                disabled={isLoading}
              />
            </div>
          ) : null}

          <div className="space-y-2">
            <Label htmlFor="password" className="flex items-center gap-2">
              <Lock className="h-4 w-4" />
              Contrasena
            </Label>
            <Input
              id="password"
              type="password"
              autoComplete={mode === "bootstrap" ? "new-password" : "current-password"}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder={mode === "bootstrap" ? "Minimo 12 caracteres" : "Tu contrasena"}
              minLength={mode === "bootstrap" ? 12 : 1}
              maxLength={256}
              required
              disabled={isLoading}
            />
          </div>

          {error ? (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/5 p-3 text-xs text-slate-400">
            {mode === "bootstrap"
              ? "Solo funciona mientras no exista ningun usuario activo. La primera cuenta recibe el rol admin."
              : "Si aun no existe una cuenta, usa Primer arranque. La API debe estar ejecutandose."}
          </div>

          <Button type="submit" className="w-full" disabled={isLoading}>
            {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {mode === "bootstrap" ? "Crear administrador" : "Iniciar sesion"}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
};
