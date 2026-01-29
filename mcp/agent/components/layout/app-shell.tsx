"use client";

import { AuroraBackground } from "@/components/ui/aurora-background";
import { Sidebar } from "@/components/layout/sidebar";

export const AppShell = ({ children }: { children: React.ReactNode }) => {
  return (
    <AuroraBackground>
      <div className="flex min-h-screen flex-col md:flex-row">
        <Sidebar />
        <main className="flex-1 px-6 py-8 md:px-10">{children}</main>
      </div>
    </AuroraBackground>
  );
};
