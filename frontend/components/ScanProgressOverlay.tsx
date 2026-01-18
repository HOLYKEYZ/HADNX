"use client";

import { useEffect, useState } from "react";
import { Loader2, CheckCircle2, Shield, Search, Lock, Server, Brain } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface ScanProgressOverlayProps {
  isVisible: boolean;
}

const SCAN_STEPS = [
  { icon: Search, label: "Resolving target DNS...", duration: 4000 },
  { icon: Server, label: "Fingerprinting server & WAF...", duration: 5500 },
  { icon: Lock, label: "Analyzing SSL/TLS Configuration...", duration: 5000 },
  { icon: Shield, label: "Checking HTTP Security Headers...", duration: 4500 },
  { icon: Search, label: "Scanning for Sensitive Cookies...", duration: 4000 },
  { icon: Brain, label: "Running AI Heuristic Analysis...", duration: 8000 }, // AI takes longer
  { icon: CheckCircle2, label: "Finalizing Security Score...", duration: 3000 },
];

export function ScanProgressOverlay({ isVisible }: ScanProgressOverlayProps) {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    if (!isVisible) {
      setCurrentStepIndex(0);
      return;
    }

    let timeoutId: NodeJS.Timeout;

    const runStep = (index: number) => {
      if (index >= SCAN_STEPS.length) return;

      timeoutId = setTimeout(() => {
        setCurrentStepIndex((prev) => prev + 1);
        runStep(index + 1);
      }, SCAN_STEPS[index].duration);
    };

    runStep(0);

    return () => clearTimeout(timeoutId);
  }, [isVisible]);

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md border-primary/20 shadow-2xl animate-in zoom-in-95 duration-300">
        <CardContent className="pt-6 pb-8">
          <div className="flex flex-col items-center justify-center text-center space-y-6">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full animate-pulse" />
              <div className="relative bg-card border border-primary/30 p-4 rounded-full">
                <Loader2 className="w-10 h-10 text-primary animate-spin" />
              </div>
            </div>

            <div className="space-y-2">
              <h2 className="text-2xl font-bold tracking-tight">Scanning Target</h2>
              <p className="text-muted-foreground">
                Initializing deep security analysis protocol...
              </p>
            </div>

            <div className="w-full space-y-3 text-left bg-muted/30 p-4 rounded-lg font-mono text-sm border border-border/50">
              {SCAN_STEPS.map((step, index) => {
                const isCompleted = index < currentStepIndex;
                const isCurrent = index === currentStepIndex;
                const isPending = index > currentStepIndex;

                return (
                  <div
                    key={index}
                    className={cn(
                      "flex items-center gap-3 transition-opacity duration-300",
                      isPending ? "opacity-30" : "opacity-100",
                      isCurrent ? "text-primary font-bold" : isCompleted ? "text-muted-foreground" : ""
                    )}
                  >
                    {isCompleted ? (
                      <CheckCircle2 className="w-4 h-4 text-green-500 shrink-0" />
                    ) : isCurrent ? (
                      <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                    ) : (
                      <step.icon className="w-4 h-4 shrink-0" />
                    )}
                    <span>{step.label}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
