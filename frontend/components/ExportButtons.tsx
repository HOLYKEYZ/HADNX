"use client";

import { Button } from "@/components/ui/button";
// import { LockedButton, PaidBadge } from "@/components/LockedFeature"; // Removed
import { Download, FileText, FileJson, Loader2 } from "lucide-react";
import { useState } from "react";

interface ExportButtonsProps {
  scanId: string;
}

export function ExportButtons({ scanId }: ExportButtonsProps) {
  const [exporting, setExporting] = useState<string | null>(null);

  const handleExport = async (format: "pdf" | "json") => {
    setExporting(format);
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:9001/api";
      
      let endpoint = "";
      if (format === "pdf") {
        endpoint = `${API_URL}/scans/${scanId}/export/pdf/`;
      } else {
        // Fallback for JSON (just get details) or future implementation
        endpoint = `${API_URL}/scans/${scanId}/`; 
      }

      const response = await fetch(endpoint, {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
        },
        credentials: "include",
      });
      
      if (!response.ok) {
        throw new Error("Export failed");
      }
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `hadnx-report-${scanId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error("Export failed:", error);
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="flex items-center gap-2">
      <Button
        variant="outline"
        className="gap-2 border-primary/50 hover:bg-primary/10 hover:text-primary transition-colors"
        onClick={() => handleExport("pdf")}
        disabled={exporting !== null}
      >
        {exporting === "pdf" ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <FileText className="w-4 h-4" />
        )}
        Export PDF
      </Button>
      
      <Button
        variant="outline"
        className="gap-2 border-primary/50 hover:bg-primary/10 hover:text-primary transition-colors"
        onClick={() => handleExport("json")}
        disabled={exporting !== null}
      >
        {exporting === "json" ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <FileJson className="w-4 h-4" />
        )}
        Export JSON
      </Button>
    </div>
  );
}
