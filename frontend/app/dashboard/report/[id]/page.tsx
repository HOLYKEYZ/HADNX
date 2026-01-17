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
  Search, // Recon
  ShieldCheck, // WAF
  Skull, // Malware
  Activity, // Threat Intel
  BrainCircuit, // AI
  Terminal, // PoC
  Copy,
  Check,
} from "lucide-react";

// ... existing code ...

  const categoryIcons: Record<string, React.ReactNode> = {
    headers: <Server className="w-5 h-5" />,
    cookies: <Cookie className="w-5 h-5" />,
    tls: <Lock className="w-5 h-5" />,
    https: <Shield className="w-5 h-5" />,
    info_disclosure: <AlertTriangle className="w-5 h-5" />,
    recon: <Search className="w-5 h-5" />,
    waf: <ShieldCheck className="w-5 h-5" />,
    malware: <Skull className="w-5 h-5" />,
    threat_intel: <Activity className="w-5 h-5" />,
    ai_analysis: <BrainCircuit className="w-5 h-5" />,
  };

  const CopyButton = ({ text }: { text: string }) => {
    const [copied, setCopied] = useState(false);
    return (
      <button
        onClick={() => {
          navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        }}
        className="absolute top-2 right-2 p-1 rounded hover:bg-muted/50 text-muted-foreground transition-colors"
      >
        {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      </button>
    );
  };

  const renderFindingCard = (finding: Finding) => {
    // Special handling for AI Report (rendered differently)
    if (finding.category === 'ai_analysis') return null;

    return (
    <div
      key={finding.id}
      className="p-4 rounded-lg border border-border bg-card/50"
    >
      <div className="flex items-start justify-between gap-4 mb-3">
        <h4 className="font-medium flex items-center gap-2">
            {finding.category === 'waf' && <ShieldCheck className="w-4 h-4 text-green-500" />}
            {finding.category === 'malware' && <Skull className="w-4 h-4 text-red-500" />}
            {finding.issue}
        </h4>
        <RiskBadge severity={finding.severity} />
      </div>
      
      {finding.description && (
          <p className="text-sm text-muted-foreground mb-3">{finding.description}</p>
      )}
      
      <p className="text-sm text-foreground/80 mb-3">{finding.impact}</p>
      
      {/* Evidence Block (Recon/Subdomains) */}
      {finding.evidence && (
        <div className="mb-4">
            <p className="text-xs font-semibold text-muted-foreground mb-1 uppercase tracking-wider">Evidence</p>
            <div className="relative rounded-md bg-muted/30 border border-border p-3">
                <pre className="text-xs overflow-x-auto whitespace-pre-wrap max-h-40 overflow-y-auto font-mono text-muted-foreground">
                    {finding.evidence}
                </pre>
            </div>
        </div>
      )}

      {/* PoC Block (Exploitation Sandbox) */}
      {finding.poc && (
        <div className="mb-4">
            <p className="text-xs font-semibold text-muted-foreground mb-1 uppercase tracking-wider flex items-center gap-1">
                <Terminal className="w-3 h-3" /> Proof of Concept
            </p>
            <div className="relative rounded-md bg-black/90 border border-border p-3 group">
                <pre className="text-xs overflow-x-auto font-mono text-green-400">
                    {finding.poc}
                </pre>
                <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                    <CopyButton text={finding.poc} />
                </div>
            </div>
        </div>
      )}

      <div className="p-3 rounded-lg bg-primary/5 border border-primary/20 mb-2">
        <p className="text-sm">
          <span className="font-medium text-primary">Recommendation: </span>
          {finding.recommendation}
        </p>
      </div>
      
      {finding.affected_element && (
        <p className="text-xs text-muted-foreground font-mono mb-2 truncate" title={finding.affected_element}>
          Affected: {finding.affected_element}
        </p>
      )}
      
      {Object.keys(finding.fix_examples).length > 0 && (
        <FixPanel fixExamples={finding.fix_examples} />
      )}
    </div>
  )};

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

      {/* AI Pentest Report (Phase 2 Feature) */}
      {scan.findings?.find(f => f.category === 'ai_analysis') && (
        <Card className="border-primary/20 bg-primary/5">
          <CardHeader className="flex flex-row items-center gap-4">
            <div className="p-2 bg-primary/10 rounded-full">
                <BrainCircuit className="w-6 h-6 text-primary" />
            </div>
            <div>
                <CardTitle className="text-xl">AI Agent Assessment</CardTitle>
                <p className="text-sm text-muted-foreground">Automated Attack Path Analysis</p>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
             {(() => {
                 const aiFinding = scan.findings?.find(f => f.category === 'ai_analysis');
                 if (!aiFinding) return null;
                 return (
                     <>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="p-4 rounded-lg bg-background/50 border border-border">
                                <h4 className="font-semibold mb-2 flex items-center gap-2">
                                    <ShieldCheck className="w-4 h-4 text-primary" /> Risk Assessment
                                </h4>
                                <p className="text-lg font-bold text-primary">{aiFinding.impact}</p>
                            </div>
                            <div className="p-4 rounded-lg bg-background/50 border border-border">
                                <h4 className="font-semibold mb-2 flex items-center gap-2">
                                    <Activity className="w-4 h-4 text-primary" /> Strategic Impact
                                </h4>
                                <p className="text-sm text-muted-foreground">
                                    Based on {scan.findings.length} findings, the AI agent has determined a {aiFinding.impact} risk profile for this asset.
                                </p>
                            </div>
                        </div>
                        
                        <div>
                            <h4 className="font-semibold mb-2">Attack Narrative</h4>
                            <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-wrap">
                                {aiFinding.description}
                            </p>
                        </div>

                        <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/20">
                            <h4 className="font-semibold mb-1 text-green-500">Recommended Next Steps</h4>
                            <pre className="text-sm whitespace-pre-wrap font-sans text-foreground/80">
                                {aiFinding.recommendation}
                            </pre>
                        </div>
                     </>
                 );
             })()}
          </CardContent>
        </Card>
      )}

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
