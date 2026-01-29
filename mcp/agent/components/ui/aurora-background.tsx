"use client";
import React, { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface AuroraBackgroundProps extends React.HTMLProps<HTMLDivElement> {
  children: ReactNode;
  showRadialGradient?: boolean;
}

export const AuroraBackground = ({
  className,
  children,
  showRadialGradient = true,
  ...props
}: AuroraBackgroundProps) => {
  return (
    <div
      className={cn(
        "relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-slate-50 text-slate-950",
        className
      )}
      {...props}
    >
      <div className="absolute inset-0">
        <div
          className={cn(
            `
            [--white-gradient:repeating-linear-gradient(120deg,#f8fafc_0%,#f8fafc_8%,transparent_12%,transparent_16%,#f8fafc_20%)]
            [--aurora:repeating-linear-gradient(120deg,#7dd3fc_10%,#a5b4fc_15%,#bae6fd_20%,#fde68a_25%,#93c5fd_30%)]
            [background-image:var(--white-gradient),var(--aurora)]
            [background-size:300%,_200%]
            [background-position:50%_50%,50%_50%]
            after:content-[""] after:absolute after:inset-0 after:[background-image:var(--white-gradient),var(--aurora)]
            after:[background-size:200%,_100%]
            after:animate-aurora
            after:opacity-70
            pointer-events-none
            absolute -inset-[10px] opacity-80`,
            showRadialGradient &&
              "[mask-image:radial-gradient(ellipse_at_60%_0%,black_15%,transparent_70%)]"
          )}
        />
      </div>
      <div className="absolute inset-0 grid-overlay" />
      <div className="relative z-10 w-full">{children}</div>
    </div>
  );
};
