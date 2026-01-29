"use client";

import { AuroraBackground } from "@/components/ui/aurora-background";
import { Sidebar } from "@/components/layout/sidebar";

export const AppShell = ({ children }: { children: React.ReactNode }) => {
  return (
    <AuroraBackground className="h-screen items-stretch justify-start">
      <div className="flex h-full min-h-0 flex-col md:flex-row">
        <Sidebar />
        <main className="flex-1 min-h-0 overflow-hidden px-6 py-8 md:px-10 flex flex-col">{children}</main>
      </div>
    </AuroraBackground>
  );
};
