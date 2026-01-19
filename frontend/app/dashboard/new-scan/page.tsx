"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { Shield, Globe, Loader2, AlertCircle, AlertTriangle, Zap } from "lucide-react";

import { ScanProgressOverlay } from "@/components/ScanProgressOverlay";

export default function NewScanPage() {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState("");
  const [exploitationEnabled, setExploitationEnabled] = useState(false);
  const [isExploitAdmin, setIsExploitAdmin] = useState(false);
  const [authorizedDomains, setAuthorizedDomains] = useState<string[]>([]);
  const router = useRouter();

  useEffect(() => {
    loadUserStatus();
  }, []);

  const loadUserStatus = async () => {
    try {
      const userData = await api.me();
      setIsExploitAdmin(userData.is_exploitation_admin || false);
      setAuthorizedDomains(userData.authorized_domains || []);
    } catch (e) {
      console.error("Failed to load user status:", e);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!url.trim()) return;

    // Validate and normalize URL
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = "https://" + targetUrl;
    }

    try {
      new URL(targetUrl);
    } catch {
      setError("Please enter a valid URL");
      return;
    }

    // If exploitation is enabled, check if domain is authorized
    if (exploitationEnabled) {
      const domain = new URL(targetUrl).hostname.toLowerCase();
      const isAuthorized = authorizedDomains.some(auth => {
        if (auth.startsWith('*.')) {
          const base = auth.slice(2);
          return domain.endsWith('.' + base) || domain === base;
        }
        return domain === auth;
      }) || domain === 'localhost' || domain === '127.0.0.1';

      if (!isAuthorized) {
        setError(`Domain "${domain}" is not in your authorized domains list. Add it in Settings first.`);
        return;
      }
    }

    setIsScanning(true);

    try {
      const data = await api.startScan(targetUrl, { exploitation_enabled: exploitationEnabled });
      // Navigate to scan progress page
      router.push(`/dashboard/scan/${data.id}`);
    } catch (err: any) {
      console.error("Scan failed:", err);
      const errorMessage = err.detail || err.error || err.message || "Failed to start scan";
      setError(errorMessage);
      setIsScanning(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-8">
      <ScanProgressOverlay isVisible={isScanning} />
      <div className="mb-8">
        <h1 className="text-3xl font-bold">New Security Scan</h1>
        <p className="text-muted-foreground mt-1">
          Analyze any website's security posture
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="w-5 h-5" />
            Enter URL to Scan
          </CardTitle>
          <CardDescription>
            We'll analyze HTTP headers, cookies, TLS/SSL configuration, and HTTPS enforcement.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleScan} className="space-y-4">
            <div>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="example.com or https://example.com"
                className="w-full h-12 px-4 rounded-lg border border-input bg-background text-base ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                disabled={isScanning}
                autoFocus
              />
            </div>

            {/* Exploitation Toggle - Admin Only */}
            {isExploitAdmin && (
              <div className="p-4 rounded-lg border border-destructive/30 bg-destructive/5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <AlertTriangle className="w-5 h-5 text-destructive" />
                    <div>
                      <p className="font-medium text-destructive">Active Exploitation</p>
                      <p className="text-sm text-muted-foreground">
                        Run real attacks (XSS, SQLi, etc.) - only on YOUR domains
                      </p>
                    </div>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={exploitationEnabled}
                      onChange={(e) => setExploitationEnabled(e.target.checked)}
                      className="sr-only peer"
                      disabled={isScanning}
                    />
                    <div className="w-11 h-6 bg-muted rounded-full peer peer-checked:after:translate-x-full peer-checked:bg-destructive after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all"></div>
                  </label>
                </div>
                
                {exploitationEnabled && (
                  <div className="mt-3 pt-3 border-t border-destructive/20">
                    <p className="text-xs text-muted-foreground mb-2">
                      Your authorized domains ({authorizedDomains.length}):
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {authorizedDomains.length === 0 ? (
                        <span className="text-xs text-destructive">No domains configured - add in Settings</span>
                      ) : (
                        authorizedDomains.map(d => (
                          <span key={d} className="px-2 py-0.5 text-xs rounded bg-destructive/10 text-destructive font-mono">
                            {d}
                          </span>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {error && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-destructive text-sm">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <Button
              type="submit"
              size="lg"
              className={`w-full ${exploitationEnabled ? 'bg-destructive hover:bg-destructive/90' : ''}`}
              disabled={isScanning || !url.trim()}
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  {exploitationEnabled ? 'Running Exploitation Scan...' : 'Processing Scan...'}
                </>
              ) : exploitationEnabled ? (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Start Exploitation Scan
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4 mr-2" />
                  Start Security Scan
                </>
              )}
            </Button>
          </form>

          <div className="mt-6 pt-6 border-t border-border">
            <h3 className="text-sm font-medium mb-3">What we analyze:</h3>
            <ul className="grid grid-cols-2 gap-2 text-sm text-muted-foreground">
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                HTTP Security Headers
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                Cookie Security Flags
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                TLS/SSL Configuration
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                HTTPS Enforcement
              </li>
              {exploitationEnabled && (
                <>
                  <li className="flex items-center gap-2 text-destructive">
                    <span className="w-1.5 h-1.5 rounded-full bg-destructive" />
                    XSS Injection Testing
                  </li>
                  <li className="flex items-center gap-2 text-destructive">
                    <span className="w-1.5 h-1.5 rounded-full bg-destructive" />
                    SQL Injection Testing
                  </li>
                  <li className="flex items-center gap-2 text-destructive">
                    <span className="w-1.5 h-1.5 rounded-full bg-destructive" />
                    SSRF & LFI Testing
                  </li>
                  <li className="flex items-center gap-2 text-destructive">
                    <span className="w-1.5 h-1.5 rounded-full bg-destructive" />
                    Auth Bypass Testing
                  </li>
                </>
              )}
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
