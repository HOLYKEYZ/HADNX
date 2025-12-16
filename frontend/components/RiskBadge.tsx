import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface RiskBadgeProps {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  className?: string;
}

export function RiskBadge({ severity, className }: RiskBadgeProps) {
  const variantMap: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    INFO: "info",
  };

  return (
    <Badge variant={variantMap[severity]} className={cn("uppercase", className)}>
      {severity}
    </Badge>
  );
}
