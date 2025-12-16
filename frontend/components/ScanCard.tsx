import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";
import type { Scan } from "@/lib/api";
import { ExternalLink, Clock, CheckCircle, XCircle, Loader2 } from "lucide-react";

interface ScanCardProps {
  scan: Scan;
}

export function ScanCard({ scan }: ScanCardProps) {
  const getStatusIcon = () => {
    switch (scan.status) {
      case "completed":
        return <CheckCircle className="w-4 h-4 text-primary" />;
      case "failed":
        return <XCircle className="w-4 h-4 text-severity-critical" />;
      case "running":
        return <Loader2 className="w-4 h-4 text-primary animate-spin" />;
      default:
        return <Clock className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const getGradeColor = (grade: string): string => {
    const colors: Record<string, string> = {
      "A+": "bg-grade-a-plus/10 text-grade-a-plus border-grade-a-plus/30",
      A: "bg-grade-a/10 text-grade-a border-grade-a/30",
      B: "bg-grade-b/10 text-grade-b border-grade-b/30",
      C: "bg-grade-c/10 text-grade-c border-grade-c/30",
      D: "bg-grade-d/10 text-grade-d border-grade-d/30",
      F: "bg-grade-f/10 text-grade-f border-grade-f/30",
    };
    return colors[grade] || "bg-muted text-muted-foreground";
  };

  return (
    <Link href={`/dashboard/report/${scan.id}`}>
      <Card className="hover:border-primary/50 transition-all cursor-pointer group">
        <CardContent className="p-4">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                {getStatusIcon()}
                <span className="font-medium truncate">{scan.domain}</span>
              </div>
              <p className="text-sm text-muted-foreground truncate mb-2">
                {scan.url}
              </p>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span>{formatDate(scan.created_at)}</span>
                {scan.status === "completed" && scan.findings_count !== undefined && (
                  <span>{scan.findings_count} findings</span>
                )}
              </div>
            </div>
            <div className="flex flex-col items-end gap-2">
              {scan.status === "completed" && scan.grade && (
                <Badge className={getGradeColor(scan.grade)}>
                  {scan.grade} ({scan.overall_score})
                </Badge>
              )}
              {scan.status === "running" && (
                <Badge variant="secondary">Scanning...</Badge>
              )}
              {scan.status === "failed" && (
                <Badge variant="destructive">Failed</Badge>
              )}
              <ExternalLink className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
