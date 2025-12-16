/**
 * API client for Hadnx backend.
 * Handles all communication with the Django REST API including Auth and CSRF.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:9001/api";

export interface Scan {
  id: string;
  url: string;
  domain: string;
  status: "pending" | "running" | "completed" | "failed";
  overall_score: number | null;
  grade: string;
  created_at: string;
  completed_at: string | null;
  findings_count?: number;
  critical_count?: number;
  high_count?: number;
}

export interface Finding {
  id: string;
  issue: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: "headers" | "cookies" | "tls" | "https" | "info_disclosure";
  impact: string;
  recommendation: string;
  fix_examples: Record<string, string>;
  affected_element: string;
  score_impact: number;
}

export interface ScanDetail extends Scan {
  headers_score: number | null;
  cookies_score: number | null;
  tls_score: number | null;
  https_score: number | null;
  error_message: string;
  findings: Finding[];
  findings_by_category: Record<string, Finding[]>;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface ScanStatus {
  id: string;
  status: "pending" | "running" | "completed" | "failed";
  overall_score: number | null;
  grade: string;
  error_message: string;
}

// Helper to get cookie by name
function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop()?.split(';').shift() || null;
  return null;
}

// Custom fetch wrapper that handles CSRF and Auth
export async function fetchWithAuth(endpoint: string, options: RequestInit = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  // Ensure headers object exists
  const headers = new Headers(options.headers || {});
  
  // Add Content-Type if not present and not FormData
  if (!headers.has("Content-Type") && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  // Get CSRF token
  let csrfToken = getCookie("csrftoken");
  
  // If no token, try to fetch it first (for initial loads)
  if (!csrfToken && typeof window !== 'undefined') {
    try {
      await fetch(`${API_BASE_URL}/auth/csrf/`, { credentials: "include" });
      csrfToken = getCookie("csrftoken");
    } catch (e) {
      console.warn("Failed to fetch initial CSRF token", e);
    }
  }

  if (csrfToken) {
    headers.set("X-CSRFToken", csrfToken);
  }

  const config = {
    ...options,
    headers,
    credentials: "include" as RequestCredentials,
  };

  const response = await fetch(url, config);
  
  // Handle 401 Unauthorized (session expired)
  if (response.status === 401) {
    if (typeof window !== 'undefined' && !window.location.pathname.includes('/login') && !window.location.pathname.includes('/register')) {
      // Clear user and redirect
      localStorage.removeItem("user");
      // Optional: window.location.href = '/login';
    }
  }

  return response;
}

export const api = {
  // Scans
  startScan: (url: string) => fetchWithAuth("/scans/", {
    method: "POST",
    body: JSON.stringify({ url }),
  }).then(async r => {
    if (!r.ok) throw await r.json();
    return r.json();
  }),

  getScans: () => fetchWithAuth("/scans/").then(r => r.json()),
  
  getScan: (id: string) => fetchWithAuth(`/scans/${id}/`).then(r => r.json()),
  
  getScanStatus: (id: string) => fetchWithAuth(`/scans/${id}/status/`).then(r => r.json()),

  deleteScan: (id: string) => fetchWithAuth(`/scans/${id}/`, { method: "DELETE" }),
  
  // Auth
  login: (data: any) => fetchWithAuth("/auth/login/", {
    method: "POST",
    body: JSON.stringify(data),
  }).then(async r => {
    const json = await r.json();
    if (!r.ok) throw json;
    return json;
  }),
  
  register: (data: any) => fetchWithAuth("/auth/register/", {
    method: "POST",
    body: JSON.stringify(data),
  }).then(async r => {
    const json = await r.json();
    if (!r.ok) throw json;
    return json;
  }),
  
  logout: () => fetchWithAuth("/auth/logout/", { method: "POST" }),
  
  me: () => fetchWithAuth("/auth/me/").then(r => r.json()),
};

export default api;
