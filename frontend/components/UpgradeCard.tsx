"use client";

import { useFeature, useFeatureGate } from "@/lib/useFeatureGate";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Sparkles, CheckCircle2, Crown } from "lucide-react";
import Link from "next/link";

export function UpgradeCard({ forceVisible = false }: { forceVisible?: boolean }) {
  const { isSaasMode, isFeatureAvailable } = useFeatureGate();
  const { available } = useFeature("advanced_scanner");
  
  // We can infer auth status if 'isFeatureAvailable' returns true for a basic feature, 
  // but better to rely on a 'user' check not exposed yet. 
  // Let's assume on the landing page (forceVisible) we want "Join Pro".
  // Inside dashboard (!forceVisible), we know they are logged in, so "Upgrade to Pro".
  
  const isLandingPage = forceVisible;
  const title = isLandingPage ? "Join Pro" : "Upgrade to Pro";
  const buttonText = isLandingPage ? "Get Started with Pro" : "Get Pro Access";

  if (!forceVisible && (!isSaasMode() || available)) {
    return null;
  }

  const benefits = [
    "Advanced Attack Simulations",
    "Compliance Mapping (OWASP, NIST)",
    "Risk Correlation Engine",
    "PDF & JSON Reports",
    "Unlimited Scan History",
  ];

  return (
    <Card className="bg-gradient-to-r from-primary/10 via-primary/5 to-transparent border-primary/20">
      <CardContent className="p-6">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-full bg-primary/20">
                <Crown className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-xl font-bold">{title}</h3>
            </div>
            
            <p className="text-muted-foreground max-w-md">
              Unlock advanced security features, compliance reports, and deep testing capabilities to secure your applications.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {benefits.map((benefit, i) => (
                <div key={i} className="flex items-center gap-2 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                  <span>{benefit}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-3 min-w-[200px]">
            <Link href="/pricing">
              <Button className="w-full gap-2" size="lg">
                <Sparkles className="w-4 h-4" />
                {buttonText}
              </Button>
            </Link>
            <p className="text-xs text-center text-muted-foreground">
              30-day money-back guarantee
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
