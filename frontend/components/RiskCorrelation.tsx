"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LockedFeature, PaidBadge } from "@/components/LockedFeature";
import { AlertTriangle, Link2, Shield, Zap } from "lucide-react";

interface AttackChain {
  name: string;
  severity: string;
  probability: string;
  findings_used: string[];
}

interface RiskCorrelationProps {
  riskScore?: number;
  riskLevel?: string;
  attackChains?: AttackChain[];
}

export function RiskCorrelation({ riskScore, riskLevel, attackChains = [] }: RiskCorrelationProps) {
  const getRiskColor = (level: string) => {
    switch (level) {
      case "CRITICAL": return "text-red-500 bg-red-500/10";
      case "HIGH": return "text-orange-500 bg-orange-500/10";
      case "MEDIUM": return "text-yellow-500 bg-yellow-500/10";
      default: return "text-green-500 bg-green-500/10";
    }
  };

  return (
    <LockedFeature feature="risk_correlation" showUpgradePrompt>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-primary" />
              Risk Correlation
            </span>
            <PaidBadge feature="risk_correlation" />
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Risk Score */}
          <div className="flex items-center justify-between p-4 rounded-lg border border-border">
            <div>
              <p className="text-sm text-muted-foreground">Correlated Risk Score</p>
              <p className="text-3xl font-bold">{riskScore ?? 0}</p>
            </div>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskColor(riskLevel || "LOW")}`}>
              {riskLevel || "LOW"}
            </div>
          </div>

          {/* Attack Chains */}
          {attackChains.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <Link2 className="w-4 h-4" />
                Detected Attack Chains
              </h4>
              {attackChains.map((chain, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg border border-border bg-card"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-sm">{chain.name}</span>
                    <span className={`text-xs px-2 py-0.5 rounded ${getRiskColor(chain.severity)}`}>
                      {chain.severity}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Based on: {chain.findings_used.slice(0, 3).join(", ")}
                    {chain.findings_used.length > 3 && ` +${chain.findings_used.length - 3} more`}
                  </p>
                </div>
              ))}
            </div>
          )}

          {attackChains.length === 0 && (
            <div className="flex items-center gap-3 p-4 rounded-lg bg-green-500/10 border border-green-500/20">
              <Shield className="w-5 h-5 text-green-500" />
              <p className="text-sm text-green-500">
                No critical attack chains detected
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </LockedFeature>
  );
}
