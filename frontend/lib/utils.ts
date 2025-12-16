import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date): string {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(date));
}

export function getGradeColor(grade: string): string {
  const colors: Record<string, string> = {
    "A+": "text-grade-a-plus",
    A: "text-grade-a",
    B: "text-grade-b",
    C: "text-grade-c",
    D: "text-grade-d",
    F: "text-grade-f",
  };
  return colors[grade] || "text-muted-foreground";
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    CRITICAL: "text-severity-critical bg-severity-critical/10 border-severity-critical/30",
    HIGH: "text-severity-high bg-severity-high/10 border-severity-high/30",
    MEDIUM: "text-severity-medium bg-severity-medium/10 border-severity-medium/30",
    LOW: "text-severity-low bg-severity-low/10 border-severity-low/30",
    INFO: "text-severity-info bg-severity-info/10 border-severity-info/30",
  };
  return colors[severity] || "";
}

export function getCategoryLabel(category: string): string {
  const labels: Record<string, string> = {
    headers: "HTTP Headers",
    cookies: "Cookies",
    tls: "TLS/SSL",
    https: "HTTPS",
    info_disclosure: "Info Disclosure",
  };
  return labels[category] || category;
}
