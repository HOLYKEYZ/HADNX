"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScoreGauge } from "@/components/charts/ScoreGauge";
import { CategoryScores } from "@/components/charts/CategoryScores";
import { RiskBreakdown } from "@/components/charts/RiskBreakdown";
import { RiskBadge } from "@/components/RiskBadge";
import { FixPanel } from "@/components/FixPanel";
import { ExportButtons } from "@/components/ExportButtons";
import { ComplianceCards } from "@/components/ComplianceCards";
import { RiskCorrelation } from "@/components/RiskCorrelation";
import { api, type ScanDetail, type Finding } from "@/lib/api";
import { formatDate, getCategoryLabel } from "@/lib/utils";
import {
  Globe,
  Calendar,
  AlertTriangle,
  Shield,
  Cookie,
  Lock,
  Server,
} from "lucide-react";

export default function ReportPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [complianceData, setComplianceData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!scanId) return;

    const loadScan = async () => {
      try {
        const data = await api.getScan(scanId);
        setScan(data);
        
        // Try to fetch compliance data (will fail if not SAAS or not authorized, which is fine)
        try {
            const comp = await api.getComplianceReport(scanId);
            console.log("Compliance data loaded:", comp);
            setComplianceData(comp);
        } catch (e) {
            console.error("Compliance data fetch failed:", e);
        }
        
      } catch (err) {
        setError("Failed to load scan report");
      } finally {
        setIsLoading(false);
      }
    };

    loadScan();
  }, [scanId]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="text-center py-12">
        <p className="text-severity-critical">{error || "Scan not found"}</p>
      </div>
    );
  }

  const categoryIcons: Record<string, React.ReactNode> = {
    headers: <Server className="w-5 h-5" />,
    cookies: <Cookie className="w-5 h-5" />,
    tls: <Lock className="w-5 h-5" />,
    https: <Shield className="w-5 h-5" />,
    info_disclosure: <AlertTriangle className="w-5 h-5" />,
  };

  const renderFindingCard = (finding: Finding) => (
    <div
      key={finding.id}
      className="p-4 rounded-lg border border-border bg-card/50"
    >
      <div className="flex items-start justify-between gap-4 mb-3">
        <h4 className="font-medium">{finding.issue}</h4>
        <RiskBadge severity={finding.severity} />
      </div>
      <p className="text-sm text-muted-foreground mb-3">{finding.impact}</p>
      <div className="p-3 rounded-lg bg-primary/5 border border-primary/20 mb-2">
        <p className="text-sm">
          <span className="font-medium text-primary">Recommendation: </span>
          {finding.recommendation}
        </p>
      </div>
      {finding.affected_element && (
        <p className="text-xs text-muted-foreground font-mono mb-2">
          Affected: {finding.affected_element}
        </p>
      )}
      {Object.keys(finding.fix_examples).length > 0 && (
        <FixPanel fixExamples={finding.fix_examples} />
      )}
    </div>
  );

  return (
    <div className="space-y-8">
      {/* Report Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <h1 className="text-3xl font-bold mb-2">Security Report</h1>
          <div className="flex flex-wrap items-center gap-4 text-muted-foreground">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4" />
              <span>{scan.domain}</span>
            </div>
            <div className="flex items-center gap-2">
              <Calendar className="w-4 h-4" />
              <span>{formatDate(scan.created_at)}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4">
           {/* Export Buttons */}
          <ExportButtons scanId={scanId} />
          <ScoreGauge
            score={scan.overall_score || 0}
            grade={scan.grade || "F"}
            size="md"
          />
        </div>
      </div>

       {/* Compliance Cards (Feature Gated) */}
      <ComplianceCards 
        scanId={scanId}
        owaspScore={complianceData?.standards?.owasp?.compliance_score}
        nistScore={complianceData?.standards?.nist?.compliance_score}
        isoScore={complianceData?.standards?.iso27001?.compliance_score}
      />

      {/* Score Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        <div className="space-y-6">
            <Card className="h-full">
            <CardHeader>
                <CardTitle>Category Scores</CardTitle>
            </CardHeader>
            <CardContent>
                <CategoryScores
                scores={{
                    headers: scan.headers_score,
                    cookies: scan.cookies_score,
                    tls: scan.tls_score,
                    https: scan.https_score,
                }}
                />
            </CardContent>
            </Card>
            
            {/* Risk Correlation (Feature Gated) */}
            <RiskCorrelation 
                riskScore={0}
                riskLevel="LOW"
                attackChains={[]}
            />
        </div>

        <Card className="h-full min-h-[300px]">
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <RiskBreakdown distribution={scan.severity_distribution || { critical: 0, high: 0, medium: 0, low: 0 }} />
          </CardContent>
        </Card>
      </div>

      {/* Findings by Category */}
      <Card>
        <CardHeader>
          <CardTitle>Security Findings</CardTitle>
        </CardHeader>
        <CardContent>
          {(scan.findings || []).length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="w-12 h-12 mx-auto mb-4 text-primary" />
              <p className="text-lg font-medium text-foreground">
                No issues found!
              </p>
              <p>Great job! Your site has a strong security posture.</p>
            </div>
          ) : (
            <Tabs defaultValue="all" className="w-full">
              <TabsList className="mb-4">
                <TabsTrigger value="all">
                  All ({(scan.findings || []).length})
                </TabsTrigger>
                {Object.entries(scan.findings_by_category || {}).map(
                  ([category, findings]) => (
                    <TabsTrigger key={category} value={category}>
                      <span className="flex items-center gap-2">
                        {categoryIcons[category]}
                        {getCategoryLabel(category)} ({(findings as any[]).length})
                      </span>
                    </TabsTrigger>
                  )
                )}
              </TabsList>

              <TabsContent value="all" className="space-y-4">
                {(scan.findings || []).map(renderFindingCard)}
              </TabsContent>

              {Object.entries(scan.findings_by_category || {}).map(
                ([category, findings]) => (
                  <TabsContent key={category} value={category} className="space-y-4">
                    {(findings as any[]).map(renderFindingCard)}
                  </TabsContent>
                )
              )}
            </Tabs>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
