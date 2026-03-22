"use client";

import { useEffect, useState } from "react";
import { Loader2, CheckCircle2, Shield, Search, Lock, Server, Brain } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface ScanProgressOverlayProps {
  isVisible: boolean;
  scanId: string;
}

const SCAN_STEPS = [
  { icon: Search, label: "Resolving target DNS...", backendStatus: "DNS_RESOLUTION" },
  { icon: Server, label: "Fingerprinting server & WAF...", backendStatus: "WAF_FINGERPRINTING" },
  { icon: Lock, label: "Analyzing SSL/TLS Configuration...", backendStatus: "SSL_ANALYSIS" },
  { icon: Shield, label: "Checking HTTP Security Headers...", backendStatus: "HEADERS_CHECK" },
  { icon: Search, label: "Scanning for Sensitive Cookies...", backendStatus: "COOKIES_SCAN" },
  { icon: Brain, label: "Running AI Heuristic Analysis...", backendStatus: "AI_ANALYSIS" },
  { icon: CheckCircle2, label: "Finalizing Security Score...", backendStatus: "COMPLETED" },
];

export function ScanProgressOverlay({ isVisible }: ScanProgressOverlayProps) {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

useEffect(() => {
  if (!isVisible) {
    setCurrentStepIndex(0);
    return;
  }

  const pollScanStatus = async () => {
    const response = await fetch(`/api/scans/${scanId}/status/`);
    const data = await response.json();
    const status = data.status;
    const stepIndex = SCAN_STEPS.findIndex((step) => step.backendStatus === status);
    if (stepIndex !== -1) {
      setCurrentStepIndex(stepIndex);
    }
  };

  const intervalId = setInterval(pollScanStatus, 2000);

  return () => clearInterval(intervalId);
}, [isVisible, scanId]);

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
