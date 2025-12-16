import { CheckCircle, XCircle, AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";

interface HeaderStatusProps {
  headers: {
    name: string;
    present: boolean;
    value?: string;
    status: "good" | "warning" | "missing";
  }[];
}

export function HeaderStatus({ headers }: HeaderStatusProps) {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case "good":
        return <CheckCircle className="w-4 h-4 text-primary" />;
      case "warning":
        return <AlertCircle className="w-4 h-4 text-severity-medium" />;
      case "missing":
        return <XCircle className="w-4 h-4 text-severity-critical" />;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-2">
      {headers.map((header) => (
        <div
          key={header.name}
          className={cn(
            "flex items-center justify-between p-3 rounded-lg border",
            header.status === "good" && "border-primary/30 bg-primary/5",
            header.status === "warning" && "border-severity-medium/30 bg-severity-medium/5",
            header.status === "missing" && "border-severity-critical/30 bg-severity-critical/5"
          )}
        >
          <div className="flex items-center gap-3">
            {getStatusIcon(header.status)}
            <span className="font-mono text-sm">{header.name}</span>
          </div>
          <span className="text-xs text-muted-foreground">
            {header.present ? "Present" : "Missing"}
          </span>
        </div>
      ))}
    </div>
  );
}
