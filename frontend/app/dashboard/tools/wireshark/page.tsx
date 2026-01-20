"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Play, Radio, Download, HelpCircle, AlertTriangle, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

export default function WiresharkPage() {
  const [interfaces, setInterfaces] = useState<{id: string, name: string}[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>("");
  const [duration, setDuration] = useState<number>(10);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [captureResult, setCaptureResult] = useState<{file: string, duration: number} | null>(null);

  useEffect(() => {
    loadInterfaces();
  }, []);

  const loadInterfaces = async () => {
    try {
      const res = await api.getWiresharkInterfaces();
      if (res.error) setError(res.error);
      else {
        setInterfaces(res.interfaces || []);
        if (res.interfaces?.length > 0) setSelectedInterface(res.interfaces[0].name);
      }
    } catch (err: any) {
      setError(err.error || "Failed to load interfaces");
    }
  };

  const startCapture = async () => {
    if (!selectedInterface) return;
    setIsLoading(true);
    setError(null);
    setCaptureResult(null);

    try {
      const res = await api.startWiresharkCapture(selectedInterface, duration);
      if (res.error) setError(res.error);
      else setCaptureResult(res);
    } catch (err: any) {
      setError(err.error || "Capture failed");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="h-[calc(100vh-6rem)] flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between p-4 bg-muted/30 border border-border rounded-lg">
        <div className="flex flex-col gap-1">
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Radio className="w-6 h-6 text-cyan-500" />
            Wireshark Packet Capture
          </h2>
          <p className="text-sm text-muted-foreground">Capture network traffic using Tshark.</p>
        </div>
        <Button variant="ghost" size="icon" onClick={loadInterfaces}><RefreshCw className="w-4 h-4" /></Button>
      </div>

      {/* Controls */}
      <Card className="border-border bg-black/20">
        <CardContent className="p-4 flex gap-4 items-end flex-wrap">
          <div className="space-y-2">
            <label className="text-sm font-medium">Network Interface</label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              className="w-64 bg-black/50 border border-border rounded px-3 py-2 text-sm font-mono"
            >
              {interfaces.length === 0 && <option value="">No interfaces found</option>}
              {interfaces.map((iface) => (
                <option key={iface.id} value={iface.name}>{iface.name}</option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">Duration (seconds)</label>
            <Input
              type="number"
              value={duration}
              onChange={(e) => setDuration(parseInt(e.target.value) || 10)}
              min={1}
              max={300}
              className="w-24 font-mono bg-black/50"
            />
          </div>
          <Button onClick={startCapture} disabled={isLoading || !selectedInterface} className="bg-cyan-600 hover:bg-cyan-700 w-40 mb-0.5">
            {isLoading ? <span className="animate-spin mr-2">⏳</span> : <Play className="w-4 h-4 mr-2 fill-current" />}
            Start Capture
          </Button>
        </CardContent>
      </Card>

      {/* Errors */}
      {error && (
        <div className="p-4 border border-destructive/50 bg-destructive/10 rounded-lg text-destructive flex items-center gap-2">
          <AlertTriangle className="w-5 h-5" /> {error}
        </div>
      )}

      {/* Result */}
      {captureResult && (
        <Card className="border-border bg-green-900/20 border-l-4 border-l-green-500">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <h3 className="font-bold text-green-400">Capture Complete!</h3>
              <p className="text-sm text-muted-foreground">Duration: {captureResult.duration}s | File: <code className="text-xs">{captureResult.file}</code></p>
            </div>
            <a href={`/api/scans/download?file=${encodeURIComponent(captureResult.file)}`} target="_blank">
              <Button variant="outline" className="gap-2">
                <Download className="w-4 h-4" /> Download .pcap
              </Button>
            </a>
          </CardContent>
        </Card>
      )}

      {/* Empty State */}
      {!captureResult && !error && !isLoading && (
        <div className="flex-1 flex items-center justify-center text-muted-foreground border border-dashed border-border rounded-lg">
          <p>Select an interface and start capturing.</p>
        </div>
      )}

      {/* Help */}
      <Card className="border-border mt-auto">
        <Accordion type="single" collapsible>
          <AccordionItem value="help" className="border-b-0">
            <AccordionTrigger className="px-4 py-3 text-sm font-medium hover:no-underline">
              <span className="flex items-center gap-2"><HelpCircle className="w-4 h-4" /> How to Use Wireshark</span>
            </AccordionTrigger>
            <AccordionContent className="px-4 pb-4 text-sm text-muted-foreground space-y-2">
              <p><strong>Prerequisites:</strong> You must have Wireshark/Tshark installed on the server. You must be logged in as an Admin.</p>
              <p><strong>Interface:</strong> Select the network interface to capture traffic on (e.g., <code>eth0</code>, <code>Wi-Fi</code>).</p>
              <p><strong>Duration:</strong> How many seconds to capture packets. Higher = larger file.</p>
              <p><strong>Download:</strong> After capture, download the <code>.pcap</code> file and open it with Wireshark Desktop for analysis.</p>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </Card>
    </div>
  );
}
