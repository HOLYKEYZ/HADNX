"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Moon, Info, Plus, X, AlertTriangle, Loader2 } from "lucide-react";
import { api } from "@/lib/api";

export default function SettingsPage() {
  const [user, setUser] = useState<any>(null);
  const [domains, setDomains] = useState<string[]>([]);
  const [newDomain, setNewDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [addingDomain, setAddingDomain] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    loadUser();
  }, []);

  const loadUser = async () => {
    try {
      const userData = await api.me();
      setUser(userData);
      setDomains(userData.authorized_domains || []);
    } catch (e) {
      console.error("Failed to load user:", e);
    }
  };

  const addDomain = async () => {
    if (!newDomain.trim()) return;
    
    setAddingDomain(true);
    setError("");
    
    try {
      const data = await api.addAuthorizedDomain(newDomain.trim().toLowerCase());
      setDomains(data.domains || []);
      setNewDomain("");
    } catch (e: any) {
      console.error("Failed to add domain:", e);
      setError(e.error || e.detail || "Failed to add domain");
    } finally {
      setAddingDomain(false);
    }
  };

  const removeDomain = async (domain: string) => {
    setLoading(true);
    try {
      const data = await api.removeAuthorizedDomain(domain);
      setDomains(data.domains || []);
    } catch (e) {
      console.error("Failed to remove domain:", e);
    } finally {
      setLoading(false);
    }
  };

  const isExploitAdmin = user?.is_exploitation_admin;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground mt-1">
          Configure your Hadnx preferences
        </p>
      </div>

      {/* Settings Cards */}
      <div className="grid gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              Scan Settings
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Default Timeout</p>
                <p className="text-sm text-muted-foreground">
                  Maximum time to wait for scan completion
                </p>
              </div>
              <select className="h-10 px-3 rounded-lg bg-card border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all outline-none text-sm">
                <option value="30">30 seconds</option>
                <option value="60">60 seconds</option>
                <option value="120">2 minutes</option>
              </select>
            </div>

            <div className="border-t border-border pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Follow Redirects</p>
                  <p className="text-sm text-muted-foreground">
                    Follow HTTP redirects during scans
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    defaultChecked
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-muted rounded-full peer peer-checked:after:translate-x-full peer-checked:bg-primary after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all"></div>
                </label>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Exploitation Admin Section - Only visible to admin */}
        {isExploitAdmin && (
          <Card className="border-destructive/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-destructive" />
                Active Exploitation (Admin Only)
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-3 bg-destructive/10 border border-destructive/30 rounded-lg">
                <p className="text-sm text-destructive font-medium">⚠ DANGER ZONE</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Active exploitation performs real attacks (XSS, SQLi, etc.) against targets.
                  Only add domains you OWN or have WRITTEN authorization to test.
                </p>
              </div>

              <div>
                <p className="font-medium mb-2">Your Authorized Domains</p>
                <p className="text-sm text-muted-foreground mb-3">
                  Domains where active exploitation is permitted. Use *.example.com for wildcards.
                </p>
                
                {/* Add domain form */}
                <div className="flex gap-2 mb-4">
                  <input
                    type="text"
                    value={newDomain}
                    onChange={(e) => setNewDomain(e.target.value)}
                    placeholder="example.com or *.example.com"
                    className="flex-1 h-10 px-3 rounded-lg bg-card border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all outline-none text-sm"
                    onKeyDown={(e) => e.key === "Enter" && addDomain()}
                  />
                  <button
                    onClick={addDomain}
                    disabled={addingDomain || !newDomain.trim()}
                    className="h-10 px-4 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    {addingDomain ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    Add
                  </button>
                </div>

                {error && (
                  <p className="text-sm text-destructive mb-3">{error}</p>
                )}
                
                {/* Domain list */}
                <div className="space-y-2">
                  {domains.length === 0 ? (
                    <div className="text-sm text-muted-foreground text-center py-6 border border-dashed border-border rounded-lg">
                      No authorized domains. Add domains above to enable exploitation.
                    </div>
                  ) : (
                    domains.map((domain) => (
                      <div
                        key={domain}
                        className="flex items-center justify-between p-3 rounded-lg bg-card border border-border"
                      >
                        <span className="font-mono text-sm">{domain}</span>
                        <button
                          onClick={() => removeDomain(domain)}
                          disabled={loading}
                          className="p-1 hover:bg-destructive/10 rounded text-destructive transition-colors"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Non-admin notice */}
        {user && !isExploitAdmin && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-muted-foreground" />
                Active Exploitation
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                Active exploitation features are restricted to authorized administrators.
                Contact your system administrator for access.
              </p>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Moon className="w-5 h-5 text-primary" />
              Appearance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Dark Mode</p>
                <p className="text-sm text-muted-foreground">
                  Always enabled for optimal viewing
                </p>
              </div>
              <span className="text-sm text-primary font-medium">Always On</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Info className="w-5 h-5 text-primary" />
              About
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Version</span>
                <span>2.0.0 (Exploitation Engine)</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Backend</span>
                <span>Django 5 + Celery</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Frontend</span>
                <span>Next.js 14</span>
              </div>
              {isExploitAdmin && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Admin Status</span>
                  <span className="text-destructive font-medium">Exploitation Admin ✓</span>
                </div>
              )}
            </div>
            
            <div className="pt-4 border-t border-border">
              <button
                onClick={() => {
                  api.logout();
                  window.location.href = "/";
                }}
                className="w-full h-10 rounded-lg bg-destructive/10 text-destructive font-medium hover:bg-destructive/20 transition-colors"
              >
                Sign Out
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
