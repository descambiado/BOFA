import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { LoginDialog } from "@/components/auth/LoginDialog";
import { authService } from "@/services/api";

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export const ProtectedRoute = ({ children }: ProtectedRouteProps) => {
  const [isAuthenticated, setIsAuthenticated] = useState(authService.isAuthenticated());
  const [showLogin, setShowLogin] = useState(!authService.isAuthenticated());

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
    setShowLogin(false);
  };

  if (!isAuthenticated) {
    return (
      <LoginDialog 
        open={showLogin} 
        onOpenChange={(open) => {
          if (!open && !authService.isAuthenticated()) {
            // Don't allow closing login if not authenticated
            setShowLogin(true);
          } else {
            setShowLogin(open);
          }
        }}
        onSuccess={handleLoginSuccess}
      />
    );
  }

  return <>{children}</>;
};