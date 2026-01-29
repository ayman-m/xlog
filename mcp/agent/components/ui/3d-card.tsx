"use client";

import React from "react";

import { cn } from "@/lib/utils";

export const CardContainer = ({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) => {
  return (
    <div className={cn("group perspective-[1000px]", className)}>
      {children}
    </div>
  );
};

export const CardBody = ({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) => {
  return (
    <div
      className={cn(
        "relative h-full w-full rounded-3xl border border-slate-200/80 bg-white/80 p-6 shadow-sm transition-all duration-300 group-hover:rotate-x-6 group-hover:-rotate-y-6 group-hover:shadow-xl",
        className
      )}
      style={{
        transformStyle: "preserve-3d",
      }}
    >
      {children}
    </div>
  );
};

export const CardItem = ({
  children,
  className,
  translateZ = 40,
}: {
  children: React.ReactNode;
  className?: string;
  translateZ?: number;
}) => {
  return (
    <div
      className={cn("transition-transform duration-300", className)}
      style={{
        transform: `translateZ(${translateZ}px)`,
      }}
    >
      {children}
    </div>
  );
};
