"use client";

import { useEffect, useState } from "react";

import { LoginScreen } from "@/components/auth/login-screen";
import { AppShell } from "@/components/layout/app-shell";

export const AuthGate = ({ children }: { children: React.ReactNode }) => {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);

  const checkStatus = async () => {
    try {
      const response = await fetch("/api/auth/status");
      const data = await response.json();
      setAuthenticated(Boolean(data.authenticated));
    } catch {
      setAuthenticated(false);
    }
  };

  useEffect(() => {
    checkStatus();
  }, []);

  if (authenticated === null) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-slate-500">
        Checking session...
      </div>
    );
  }

  if (!authenticated) {
    return <LoginScreen onSuccess={checkStatus} />;
  }

  return <AppShell>{children}</AppShell>;
};
