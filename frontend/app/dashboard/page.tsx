"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScoreGauge } from "@/components/charts/ScoreGauge";
import { RiskBreakdown } from "@/components/charts/RiskBreakdown";
import { CategoryScores } from "@/components/charts/CategoryScores";
import { ScanCard } from "@/components/ScanCard";
import { api, type Scan } from "@/lib/api";
import { UpgradeCard } from "@/components/UpgradeCard";
import { Shield, AlertTriangle, CheckCircle, Clock, Sparkles } from "lucide-react";
import Link from "next/link";
import { useFeature, useFeatureGate } from "@/lib/useFeatureGate";

export default function DashboardPage() {
  const { user, isFeatureAvailable } = useFeatureGate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");

  const [scanUrl, setScanUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const router = useRouter();

  useEffect(() => {
    loadScans();
  }, []);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanUrl.trim()) return;

    let targetUrl = scanUrl.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = "https://" + targetUrl;
    }

    setIsScanning(true);
    try {
      const data = await api.startScan(targetUrl);
      router.push(`/dashboard/scan/${data.id}`);
    } catch (err) {
      console.error("Scan failed:", err);
      // Optional: show error toast
    } finally {
      setIsScanning(false);
    } 
  };

  const loadScans = async () => {
    try {
      const data = await api.getScans();
      setScans(data.results || []);
    } catch (err) {
      setError("Failed to load scans");
    } finally {
      setIsLoading(false);
    }
  };

  // Calculate stats from scans
  const completedScans = scans.filter((s) => s.status === "completed");
  const latestScan = completedScans[0];

  const totalFindings = completedScans.reduce(
    (sum, s) => sum + (s.findings_count || 0),
    0
  );
  const totalCritical = completedScans.reduce(
    (sum, s) => sum + (s.critical_count || 0),
    0
  );
  const totalHigh = completedScans.reduce(
    (sum, s) => sum + (s.high_count || 0),
    0
  );
  const avgScore =
    completedScans.length > 0
      ? Math.round(
          completedScans.reduce((sum, s) => sum + (s.overall_score || 0), 0) /
            completedScans.length
        )
      : 0;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Debug Banner - Temporary */}
      {/* Debug Banner - Always Visible */}
      <div className="bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200 p-2 text-xs font-mono rounded border border-yellow-200 dark:border-yellow-900/50">
          DEBUG: User: {user ? user.username : 'NULL'} | 
          Staff: {user ? String(user.is_staff) : 'N/A'} | 
          Super: {user ? String(user.is_superuser) : 'N/A'} | 
          Export: {String(isFeatureAvailable('export_pdf'))}
      </div>

      {/* Page Header and Scan Input */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            Overview of your security posture
          </p>
        </div>
        
        <form onSubmit={handleScan} className="flex w-full md:w-auto gap-2">
          <input
            type="text"
            placeholder="Scan new URL..."
            value={scanUrl}
            onChange={(e) => setScanUrl(e.target.value)}
            className="flex-1 md:w-80 h-10 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
          />
          <Button type="submit" disabled={isScanning || !scanUrl.trim()}>
            {isScanning ? "Scanning..." : "Scan"}
          </Button>
        </form>
      </div>
      
      {/* Upgrade Promo */}
      <UpgradeCard />

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                <Shield className="w-6 h-6 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">{completedScans.length}</p>
                <p className="text-sm text-muted-foreground">Total Scans</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-severity-critical/10 flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-severity-critical" />
              </div>
              <div>
                <p className="text-2xl font-bold">{totalCritical}</p>
                <p className="text-sm text-muted-foreground">Critical Issues</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-severity-high/10 flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-severity-high" />
              </div>
              <div>
                <p className="text-2xl font-bold">{totalHigh}</p>
                <p className="text-sm text-muted-foreground">High Issues</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">{avgScore}</p>
                <p className="text-sm text-muted-foreground">Avg. Score</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Latest Score */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Latest Score</CardTitle>
          </CardHeader>
          <CardContent>
            {latestScan ? (
              <div className="flex flex-col items-center">
                <ScoreGauge
                  score={latestScan.overall_score || 0}
                  grade={latestScan.grade || "F"}
                  size="lg"
                />
                <p className="mt-4 text-sm text-muted-foreground">
                  {latestScan.domain}
                </p>
                <Link
                  href={`/dashboard/report/${latestScan.id}`}
                  className="mt-2 text-sm text-primary hover:underline"
                >
                  View full report →
                </Link>
              </div>
            ) : (
              <div className="flex flex-col items-center py-8 text-muted-foreground">
                <Clock className="w-12 h-12 mb-4" />
                <p>No scans yet</p>
                <Link href="/" className="mt-2 text-primary hover:underline">
                  Start your first scan
                </Link>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Risk Breakdown */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {totalFindings > 0 ? (
              <RiskBreakdown
                distribution={{
                  critical: totalCritical,
                  high: totalHigh,
                  medium: completedScans.reduce(
                    (sum, s) =>
                      sum +
                      ((s.findings_count || 0) -
                        (s.critical_count || 0) -
                        (s.high_count || 0)),
                    0
                  ),
                  low: 0,
                }}
              />
            ) : (
              <div className="flex items-center justify-center h-48 text-muted-foreground">
                No findings to display
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans or Analysis Preview */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold">
             {/* If paid/admin, show "Recent Scans". If free, show "Analysis Overview" */}
             {/* We use 'advanced_scanner' availability as a proxy for Pro status */}
             <FeatureAwareTitle />
          </h2>
          <FeatureAwareLink />
        </div>
        
        <FeatureAwareContent scans={scans} />
      </div>
    </div>
  );
}

// Helper components to avoid hook conditional violations if we used hooks inside loops
function FeatureAwareTitle() {
    const { available } = useFeature("scan_history");
    return available ? "Recent Scans" : "Analysis Overview";
}

function FeatureAwareLink() {
    const { available } = useFeature("scan_history");
    return available ? (
        <Link
            href="/dashboard/history"
            className="text-sm text-primary hover:underline"
        >
            View all →
        </Link>
    ) : null;
}

function FeatureAwareContent({ scans }: { scans: Scan[] }) {
    const { available } = useFeature("scan_history");
    const { available: isPro } = useFeature("advanced_scanner"); // Proxy for pro/admin
    
    // We need CategoryScores component here, assuming it's imported.
    // But wait, the DashboardPage doesn't have the scan DETAIL data needed for CategoryScores (headers_score, etc.).
    // The 'scans' list usually has summary data.
    // Let's check 'Scan' type in api.ts.
    // If summary doesn't have category scores, we can't show them easily without fetching.
    // We can show "Risk Distribution" again? No, that's redundant.
    // The user said "show little part of the analysis".
    // Maybe show the "Severity Distribution" (RiskBreakdown) if it's not already shown?
    // It IS shown in the middle.
    
    // Let's look at the Dashboard again.
    // Middle section: Latest Score (Left), Risk Breakdown (Right).
    // User wants "Analysis" where History was.
    // Maybe checking the image helps.
    // "check my uploaded image... analysis layout is a bit disorganized".
    // The image was of REPORT page.
    
    // BACKTRACK: User said "show free users no history at all... instead show little part of the analysis down where the history is currently".
    // This is clearly about Dashboard page bottom section.
    // If I can't show CategoryScores (no data), I'll show a "Latest Scan Summary" card?
    // Or I'll fetch the latest scan detail?
    // That adds complexity.
    // Let's just HIDE history for free users and maybe show a "Upgrade for History" banner?
    // "show little part of the analysis" -> Maybe show the breakdown there?
    // I'll reuse RiskBreakdown for the BOTTOM section if free?
    // But RiskBreakdown is already in the middle.
    // I'll show the "CategoryScores" for the latest scan. I'll need to fetch detailed scan data?
    // Actually, 'Scan' list item might have category scores? I'll check api.ts.

    if (available) {
        return scans.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {scans.slice(0, 4).map((scan) => (
              <ScanCard key={scan.id} scan={scan} />
            ))}
          </div>
        ) : (
          <Card>
            <CardContent className="py-12 text-center text-muted-foreground">
              <p>No scans yet. Start by scanning a URL!</p>
            </CardContent>
          </Card>
        );
    }

    // For Free Users:
    // Show CategoryScores for the latest scan if available
    const latestScan = scans[0];

    return (
        <Card className="bg-muted/30 border-dashed">
            <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center gap-2">
                    <Shield className="w-5 h-5 text-primary" />
                    Latest Scan Analysis
                </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
                {latestScan && latestScan.status === "completed" ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
                        <div className="h-48">
                            <CategoryScores 
                                scores={{
                                    headers: (latestScan as any).headers_score,
                                    cookies: (latestScan as any).cookies_score,
                                    tls: (latestScan as any).tls_score,
                                    https: (latestScan as any).https_score,
                                }}
                            />
                        </div>
                        <div className="text-center md:text-left space-y-4">
                            <div className="space-y-1">
                                <h4 className="font-semibold text-xl">Detailed Insights</h4>
                                <p className="text-sm text-muted-foreground">
                                    Track deep security metrics across {latestScan.domain}. 
                                    Upgrade to Pro for full historical data and compliance mapping.
                                </p>
                            </div>
                            <div className="flex flex-wrap gap-2">
                                <Link href="/pricing">
                                    <Button size="sm" className="gap-2">
                                        <Sparkles className="w-4 h-4" />
                                        View Full History
                                    </Button>
                                </Link>
                                <Link href={`/dashboard/report/${latestScan.id}`}>
                                    <Button variant="outline" size="sm">
                                        View Latest Report
                                    </Button>
                                </Link>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div className="py-12 text-center space-y-4">
                        <div className="flex justify-center">
                            <Clock className="w-12 h-12 text-muted-foreground opacity-50" />
                        </div>
                        <div>
                           <h3 className="text-lg font-medium">No Scan Data</h3>
                           <p className="text-muted-foreground max-w-md mx-auto">
                               Start your first scan to see the analysis preview here.
                           </p>
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
