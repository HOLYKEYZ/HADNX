/**
 * API client for Hadnx backend.
 * Handles all communication with the Django REST API including Auth and CSRF.
 */

let API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:9001/api";

// Force direct backend connection in local development to avoid Next.js proxy loops
if (typeof window !== 'undefined' && window.location.hostname === 'localhost') {
  API_BASE_URL = "http://localhost:9001/api";
}

console.log("Current API_BASE_URL:", API_BASE_URL);

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
  exploitation_enabled?: boolean;
}

export interface Finding {
  id: string;
  issue: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: "headers" | "cookies" | "tls" | "https" | "info_disclosure" | "recon" | "waf" | "malware" | "threat_intel" | "ai_analysis";
  impact: string;
  recommendation: string;
  fix_examples: Record<string, string>;
  affected_element: string;
  score_impact: number;
  poc?: string;      // New for Exploitation Sandbox
  evidence?: string; // New for Subdomains/Recon
  confidence?: string; // New for WAF/Malware
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
    if (typeof window !== 'undefined' && 
        !window.location.pathname.includes('/login') && 
        !window.location.pathname.includes('/register')) {
      
      // Only force logout if we are sure it's an auth token issue, 
      // or if we are not on a public page where 401 might be expected (unlikely for fetchWithAuth).
      // But let's be careful. If a scan fails with 401, it means session is gone.
      // So logout IS correct behavior for session-based auth.
      // However, user claims "Try Again" logs them out. 
      // This implies their session IS invalid.
      // Why is it invalid? 
      
      localStorage.removeItem("user");
      // Redirect to login to make it obvious
      window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
    }
  }

  return response;
}

export const api = {
  // Scans
  startScan: (url: string, options?: { exploitation_enabled?: boolean }) => fetchWithAuth("/scans/", {
    method: "POST",
    body: JSON.stringify({ url, exploitation_enabled: options?.exploitation_enabled || false }),
  }).then(async r => {
    if (!r.ok) throw await r.json();
    return r.json();
  }),

  getScans: () => fetchWithAuth("/scans/").then(async r => {
    const data = await r.json();
    // Handle DRF pagination (data.results)
    if (data.results && Array.isArray(data.results)) {
        return data.results;
    }
    return Array.isArray(data) ? data : [];
  }),
  
  getScan: (id: string) => fetchWithAuth(`/scans/${id}/`).then(r => r.json()),
  
  getScanStatus: (id: string) => fetchWithAuth(`/scans/${id}/status/`).then(r => r.json()),

  // Compliance & Advanced Features
  getComplianceReport: (scanId: string) => fetchWithAuth(`/compliance/${scanId}/`).then(r => r.json()),
  
  getOWASPReport: (scanId: string) => fetchWithAuth(`/compliance/${scanId}/owasp/`).then(r => r.json()),
  
  getNISTReport: (scanId: string) => fetchWithAuth(`/compliance/${scanId}/nist/`).then(r => r.json()),
  
  getISOReport: (scanId: string) => fetchWithAuth(`/compliance/${scanId}/iso27001/`).then(r => r.json()),

  deleteScan: (id: string) => fetchWithAuth(`/scans/${id}/`, { method: "DELETE" }),
  
  // Auth
  login: (data: any) => fetchWithAuth("/auth/login/", {
    method: "POST",
    body: JSON.stringify(data),
  }).then(async r => {
    let json;
    try {
      json = await r.json();
    } catch (e) {
      const text = await r.text().catch(() => "No body");
      console.error(`Login failed: ${r.status} ${r.statusText}`, text.substring(0, 200));
      throw new Error(`Server returned ${r.status} (${r.statusText}). Check console.`);
    }
    
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

  // Authorized Domains
  addAuthorizedDomain: (domain: string) => fetchWithAuth("/auth/authorized-domains/", {
    method: "POST",
    body: JSON.stringify({ domain }),
  }).then(async r => {
    if (!r.ok) throw await r.json();
    return r.json();
  }),

  removeAuthorizedDomain: (domain: string) => fetchWithAuth("/auth/authorized-domains/", {
    method: "DELETE",
    body: JSON.stringify({ domain }),
  }).then(async r => {
    if (!r.ok) throw await r.json();
    return r.json();
  }),

  // AI & Chat
  chatWithAI: (scanId: string, messages: any[]) => fetchWithAuth(`/scans/${scanId}/chat/`, {
    method: "POST",
    body: JSON.stringify({ messages }),
  }).then(async r => {
    if (!r.ok) throw await r.json();
    return r.json();
  }),

  analyzeFinding: (scanId: string, findingId: number) => fetchWithAuth(`/scans/${scanId}/analyze_finding/`, {
    method: "POST",
    body: JSON.stringify({ finding_id: findingId }),
  }).then(async r => {
    if (!r.ok) throw await r.json();
    return r.json();
  }),

  // Manual Tools
  sendRepeaterRequest: (data: any) => fetchWithAuth("/scans/repeater/", {
    method: "POST",
    body: JSON.stringify(data),
  }).then(async r => {
    // Return the response object even if status is not 200 (for 4xx/5xx debugging)
    // The backend wraps the actual response in a 200 JSON with 'status' field,
    // unless the Repeater itself crashes (502).
    if (!r.ok) throw await r.json();
    return r.json();
  }),
};

export default api;
