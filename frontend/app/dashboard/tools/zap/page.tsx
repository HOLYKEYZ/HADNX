"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Play, ShieldCheck, Bug, RefreshCw, AlertTriangle, HelpCircle, Wifi, WifiOff } from "lucide-react";
import { api } from "@/lib/api";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

export default function ZapPage() {
  const [url, setUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState<boolean | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanType, setScanType] = useState<"spider" | "active_scan">("spider");
  const [progress, setProgress] = useState<string>("0");
  const [alerts, setAlerts] = useState<any[]>([]);

  // Check ZAP connection on mount
  useEffect(() => {
    checkConnection();
  }, []);

  const checkConnection = async () => {
    try {
      const res = await api.runZapAction({ action: "check" });
      setConnected(res.connected);
      if (!res.connected) setError(res.error || "ZAP not running");
    } catch (err: any) {
      setConnected(false);
      setError(err.error || "Cannot connect to ZAP");
    }
  };

  const startScan = async (type: "spider" | "active_scan") => {
    if (!url) return;
    setIsLoading(true);
    setError(null);
    setAlerts([]);
    setScanType(type);
    setProgress("0");

    try {
      const res = await api.runZapAction({ action: type, url });
      if (res.error) {
        setError(res.error);
      } else {
        setScanId(res.scan_id);
        pollStatus(res.scan_id, type);
      }
    } catch (err: any) {
      setError(err.error || "Scan failed");
      setIsLoading(false);
    }
  };

  const pollStatus = async (id: string, type: "spider" | "active_scan") => {
    const interval = setInterval(async () => {
      try {
        const res = await api.runZapAction({ action: "status", scan_id: id, scan_type: type });
        setProgress(res.progress || "0");
        if (res.status === "completed") {
          clearInterval(interval);
          setIsLoading(false);
          fetchAlerts();
        }
      } catch (e) {
        clearInterval(interval);
        setIsLoading(false);
      }
    }, 2000);
  };

  const fetchAlerts = async () => {
    if (!url) return;
    try {
      const res = await api.runZapAction({ action: "alerts", url });
      setAlerts(res.alerts || []);
    } catch (e) {}
  };

  return (
    <div className="h-[calc(100vh-6rem)] flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between p-4 bg-muted/30 border border-border rounded-lg">
        <div className="flex flex-col gap-1">
          <h2 className="text-xl font-bold flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-green-500" />
            OWASP ZAP Scanner
          </h2>
          <p className="text-sm text-muted-foreground">Comprehensive web vulnerability scanner.</p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          {connected === null ? (
            <span className="text-muted-foreground">Checking ZAP...</span>
          ) : connected ? (
            <span className="flex items-center gap-1 text-green-500"><Wifi className="w-4 h-4" /> ZAP Connected</span>
          ) : (
            <span className="flex items-center gap-1 text-destructive"><WifiOff className="w-4 h-4" /> ZAP Offline</span>
          )}
          <Button variant="ghost" size="icon" onClick={checkConnection}><RefreshCw className="w-4 h-4" /></Button>
        </div>
      </div>

      {/* Input */}
      <Card className="border-border bg-black/20">
        <CardContent className="p-4 flex gap-4 items-end">
          <div className="flex-1 space-y-2">
            <label className="text-sm font-medium">Target URL</label>
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="font-mono bg-black/50"
              disabled={!connected}
            />
          </div>
          <Button onClick={() => startScan("spider")} disabled={isLoading || !connected} className="bg-blue-600 hover:bg-blue-700 w-32 mb-0.5">
            {isLoading && scanType === "spider" ? <span className="animate-spin mr-2">⏳</span> : <Bug className="w-4 h-4 mr-2" />}
            Spider
          </Button>
          <Button onClick={() => startScan("active_scan")} disabled={isLoading || !connected} className="bg-red-600 hover:bg-red-700 w-40 mb-0.5">
            {isLoading && scanType === "active_scan" ? <span className="animate-spin mr-2">⏳</span> : <Play className="w-4 h-4 mr-2 fill-current" />}
            Active Scan
          </Button>
        </CardContent>
      </Card>

      {/* Progress */}
      {isLoading && (
        <div className="p-4 border border-border rounded-lg bg-muted/10 flex items-center gap-4">
          <span className="text-sm font-medium">Scan Progress:</span>
          <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
            <div className="h-full bg-green-500 transition-all" style={{ width: `${progress}%` }} />
          </div>
          <span className="text-sm font-mono">{progress}%</span>
        </div>
      )}

      {/* Errors */}
      {error && (
        <div className="p-4 border border-destructive/50 bg-destructive/10 rounded-lg text-destructive flex items-center gap-2">
          <AlertTriangle className="w-5 h-5" /> {error}
        </div>
      )}

      {/* Alerts */}
      <div className="flex-1 min-h-0 overflow-auto space-y-2">
        {alerts.length === 0 && !isLoading && url && (
          <div className="p-8 text-center text-muted-foreground border border-dashed border-border rounded-lg">
            No alerts yet. Run a scan to see findings.
          </div>
        )}
        {alerts.map((alert, i) => (
          <Card key={i} className={`border-l-4 ${
            alert.risk === "High" ? "border-l-red-500" :
            alert.risk === "Medium" ? "border-l-orange-500" :
            alert.risk === "Low" ? "border-l-yellow-500" : "border-l-blue-500"
          } bg-black/10`}>
            <CardContent className="p-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="font-bold">{alert.alert}</h3>
                  <p className="text-xs text-muted-foreground mt-1">{alert.url}</p>
                </div>
                <span className={`px-2 py-0.5 rounded text-xs uppercase font-bold text-white ${
                  alert.risk === "High" ? "bg-red-600" :
                  alert.risk === "Medium" ? "bg-orange-600" :
                  alert.risk === "Low" ? "bg-yellow-600" : "bg-blue-600"
                }`}>{alert.risk}</span>
              </div>
              <p className="text-sm mt-2 text-muted-foreground">{alert.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Help */}
      <Card className="border-border">
        <Accordion type="single" collapsible>
          <AccordionItem value="help" className="border-b-0">
            <AccordionTrigger className="px-4 py-3 text-sm font-medium hover:no-underline">
              <span className="flex items-center gap-2"><HelpCircle className="w-4 h-4" /> How to Use ZAP</span>
            </AccordionTrigger>
            <AccordionContent className="px-4 pb-4 text-sm text-muted-foreground space-y-2">
              <p><strong>Prerequisites:</strong> You must have OWASP ZAP running locally on <code>127.0.0.1:8080</code> (default).</p>
              <p><strong>Spider:</strong> Crawls the target to discover pages.</p>
              <p><strong>Active Scan:</strong> Attacks discovered pages to find vulnerabilities (SQL Injection, XSS, etc.).</p>
              <p><strong>Tip:</strong> Run Spider first, then Active Scan for best results.</p>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </Card>
    </div>
  );
}
