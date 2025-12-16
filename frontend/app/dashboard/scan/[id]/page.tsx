"use client";

import { useEffect, useState } from "react";
import { useRouter, useParams } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { ScoreGauge } from "@/components/charts/ScoreGauge";
import { api, type ScanStatus } from "@/lib/api";
import { Shield, Loader2, CheckCircle, XCircle } from "lucide-react";

export default function ScanProgressPage() {
  const router = useRouter();
  const params = useParams();
  const scanId = params.id as string;

  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!scanId) return;

    const pollStatus = async () => {
      try {
        const data = await api.getScanStatus(scanId);
        setStatus(data);

        if (data.status === "completed") {
          // Redirect to report after a short delay
          setTimeout(() => {
            router.push(`/dashboard/report/${scanId}`);
          }, 1500);
        } else if (data.status === "failed") {
          setError(data.error_message || "Scan failed");
        } else {
          // Continue polling
          setTimeout(pollStatus, 2000);
        }
      } catch (err) {
        setError("Failed to get scan status");
      }
    };

    pollStatus();
  }, [scanId, router]);

  const renderContent = () => {
    if (error) {
      return (
        <div className="text-center">
          <div className="w-16 h-16 rounded-full bg-severity-critical/10 flex items-center justify-center mx-auto mb-6">
            <XCircle className="w-8 h-8 text-severity-critical" />
          </div>
          <h2 className="text-2xl font-bold mb-2">Scan Failed</h2>
          <p className="text-muted-foreground mb-6">{error}</p>
          <button
            onClick={() => router.push("/")}
            className="px-6 py-2 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors"
          >
            Try Again
          </button>
        </div>
      );
    }

    if (status?.status === "completed") {
      return (
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <ScoreGauge
              score={status.overall_score || 0}
              grade={status.grade || "F"}
              size="lg"
            />
          </div>
          <h2 className="text-2xl font-bold mb-2">Scan Complete!</h2>
          <p className="text-muted-foreground">Redirecting to report...</p>
        </div>
      );
    }

    return (
      <div className="text-center">
        <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-6 animate-pulse">
          <Loader2 className="w-8 h-8 text-primary animate-spin" />
        </div>
        <h2 className="text-2xl font-bold mb-2">Scanning...</h2>
        <p className="text-muted-foreground mb-8">
          Analyzing security posture. This may take a few moments.
        </p>

        {/* Progress Steps */}
        <div className="max-w-md mx-auto space-y-4 text-left">
          {[
            { label: "Fetching URL", complete: true },
            { label: "Analyzing HTTP Headers", complete: status?.status === "running" },
            { label: "Checking Cookie Security", complete: false },
            { label: "Verifying TLS/SSL", complete: false },
            { label: "Detecting Mixed Content", complete: false },
            { label: "Calculating Score", complete: false },
          ].map((step, i) => (
            <div key={i} className="flex items-center gap-3">
              {step.complete ? (
                <CheckCircle className="w-5 h-5 text-primary" />
              ) : (
                <div className="w-5 h-5 rounded-full border-2 border-border" />
              )}
              <span
                className={
                  step.complete ? "text-foreground" : "text-muted-foreground"
                }
              >
                {step.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-[60vh] flex items-center justify-center">
      <Card className="w-full max-w-lg">
        <CardContent className="py-12">{renderContent()}</CardContent>
      </Card>
    </div>
  );
}
