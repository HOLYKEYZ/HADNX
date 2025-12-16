"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScoreGauge } from "@/components/charts/ScoreGauge";
import { RiskBreakdown } from "@/components/charts/RiskBreakdown";
import { ScanCard } from "@/components/ScanCard";
import { api, type Scan } from "@/lib/api";
import { Shield, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import Link from "next/link";

export default function DashboardPage() {
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

      {/* Recent Scans */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold">Recent Scans</h2>
          <Link
            href="/dashboard/history"
            className="text-sm text-primary hover:underline"
          >
            View all →
          </Link>
        </div>
        {scans.length > 0 ? (
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
        )}
      </div>
    </div>
  );
}
