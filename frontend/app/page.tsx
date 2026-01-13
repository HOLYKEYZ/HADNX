"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, ArrowRight, Lock, Cookie, Server, Zap } from "lucide-react";
import { UpgradeCard } from "@/components/UpgradeCard";

import { api } from "@/lib/api";

export default function HomePage() {
  const [url, setUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    // Validate URL
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

    setIsLoading(true);

    try {
      const data = await api.startScan(targetUrl);
      router.push(`/dashboard/scan/${data.id}`);
    } catch (err: any) {
      console.error("Scan error:", err);
      // Check for trial limit error
      if (err.error === 'trial_limit_exceeded' || err.limit_reached) {
        setError("You've reached the free trial limit (2 scans). Please sign up to continue.");
        // Could also redirect or show a modal here
      } else {
        const errorMessage = err.detail || err.error || "Failed to start scan. Please check if the backend is running.";
        setError(errorMessage);
      }
      setIsLoading(false);
    }
  };

  const features = [
    {
      icon: Server,
      title: "HTTP Headers",
      description: "Analyze security headers like CSP, HSTS, and X-Frame-Options",
    },
    {
      icon: Cookie,
      title: "Cookie Security",
      description: "Check Secure, HttpOnly, and SameSite flags on all cookies",
    },
    {
      icon: Lock,
      title: "TLS/SSL Analysis",
      description: "Verify TLS version, cipher strength, and certificate validity",
    },
    {
      icon: Zap,
      title: "HTTPS Enforcement",
      description: "Detect mixed content and HTTP to HTTPS redirects",
    },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-border/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img
              src="/logo.png"
              alt="Hadnx Logo"
              className="w-10 h-10 rounded-lg"
            />
            <span className="text-xl font-bold">Hadnx</span>
          </div>
          <nav className="flex items-center gap-6">
            <a href="/login" className="text-muted-foreground hover:text-foreground transition-colors">
              Sign In
            </a>
            <a href="/register" className="px-4 py-2 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors">
              Sign Up
            </a>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1 flex flex-col items-center justify-center px-6 py-20">
        <div className="max-w-3xl mx-auto text-center space-y-8">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-sm">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            <span className="text-primary">Defensive Security Analysis</span>
          </div>

          {/* Headline */}
          <h1 className="text-5xl md:text-6xl font-bold tracking-tight">
            <span className="text-glow">Security Posture</span>
            <br />
            <span className="text-muted-foreground">Analysis Made Simple</span>
          </h1>

          {/* Subheadline */}
          <p className="text-lg text-muted-foreground max-w-xl mx-auto">
            Scan any website for security vulnerabilities. Get actionable fixes
            with framework-specific remediation guidance.
          </p>

          {/* Scan Input */}
          <form onSubmit={handleScan} className="max-w-xl mx-auto">
             <div className="flex justify-end mb-2">
                <span className="text-xs font-medium text-primary px-2 py-1 bg-primary/10 rounded-full border border-primary/20">
                    Free Trial: 2 scans per session
                </span>
             </div>
            <div className="relative flex items-center">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL to scan (e.g., example.com)"
                className="w-full h-14 px-6 pr-36 rounded-xl bg-card border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all outline-none text-base"
                disabled={isLoading}
              />
              <button
                type="submit"
                disabled={isLoading || !url.trim()}
                className="absolute right-2 h-10 px-6 rounded-lg bg-primary text-primary-foreground font-medium flex items-center gap-2 hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    Scan Now
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
            {error && (
              <p className="mt-3 text-sm text-red-400">{error}</p>
            )}
          </form>
        </div>

        {/* Features Grid */}
        <div className="mt-24 w-full max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature) => (
            <div
              key={feature.title}
              className="p-6 rounded-xl bg-card border border-border hover:border-primary/50 transition-colors group"
            >
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                <feature.icon className="w-6 h-6 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">{feature.title}</h3>
              <p className="text-sm text-muted-foreground">
                {feature.description}
              </p>
            </div>
          ))}
        </div>

        {/* Upgrade Promo Section */}
        <div className="mt-20 w-full max-w-4xl mx-auto">
          <UpgradeCard forceVisible={true} />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border/50 py-8">
        <div className="container mx-auto px-6 text-center text-sm text-muted-foreground">
          <p>Hadnx — Defensive security scanning. No exploits, no payloads.</p>
        </div>
      </footer>
    </div>
  );
}
