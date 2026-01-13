"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LockedFeature, PaidBadge } from "@/components/LockedFeature";
import { Shield, FileCheck, Building2 } from "lucide-react";
import Link from "next/link";

interface ComplianceCardProps {
  scanId: string;
  owaspScore?: number;
  nistScore?: number;
  isoScore?: number;
}

export function ComplianceCards({ scanId, owaspScore, nistScore, isoScore }: ComplianceCardProps) {
  const standards = [
    {
      id: "owasp",
      name: "OWASP Top 10",
      icon: Shield,
      score: owaspScore,
      color: "text-red-500",
      href: `/dashboard/compliance/${scanId}/owasp`,
    },
    {
      id: "nist",
      name: "NIST 800-53",
      icon: FileCheck,
      score: nistScore,
      color: "text-blue-500",
      href: `/dashboard/compliance/${scanId}/nist`,
    },
    {
      id: "iso",
      name: "ISO 27001",
      icon: Building2,
      score: isoScore,
      color: "text-green-500",
      href: `/dashboard/compliance/${scanId}/iso27001`,
    },
  ];

  return (
    <LockedFeature feature="compliance" showUpgradePrompt>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {standards.map((standard) => (
          <Link key={standard.id} href={standard.href}>
            <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <standard.icon className={`w-4 h-4 ${standard.color}`} />
                    {standard.name}
                  </span>
                  <PaidBadge feature="compliance" />
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {standard.score !== undefined ? (
                    <span className={standard.score >= 80 ? "text-green-500" : standard.score >= 60 ? "text-yellow-500" : "text-red-500"}>
                      {standard.score}%
                    </span>
                  ) : (
                    <span className="text-muted-foreground">--</span>
                  )}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Compliance Score
                </p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </LockedFeature>
  );
}
