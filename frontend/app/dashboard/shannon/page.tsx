
"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Play, Square, Terminal, Shield, AlertTriangle } from "lucide-react";

export default function ShannonPage() {
  const [target, setTarget] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [findings, setFindings] = useState<any[]>([]);

  const addLog = (msg: string) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const startAudit = async () => {
    if (!target) return;
    setIsScanning(true);
    setLogs([]);
    setFindings([]);
    addLog(`Starting Shannon Agent on target: ${target}`);
    addLog("Initializing autonomous recon modules...");

    try {
      // API Call to Backend
      const res = await fetch("/api/scans/shannon/audit/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });

      if (!res.ok) {
        throw new Error("Audit failed to start");
      }

      const data = await res.json();
      
      // Simulate streaming/processing result (since backend returns generic JSON string currently)
      addLog("Agent connected. Analyzing attack surface...");
      
      // If result is string, try to parse or show as raw
      let resultObj = data.result;
      if (typeof data.result === "string") {
           try {
               resultObj = JSON.parse(data.result);
           } catch (e) {
               addLog("Raw Output: " + data.result);
           }
      }

      if (resultObj) {
          addLog("Analysis Complete.");
          if (resultObj.narrative) addLog(resultObj.narrative);
          
          if (resultObj.vectors) {
              setFindings(resultObj.vectors);
              addLog(`Identified ${resultObj.vectors.length} potential attack vectors.`);
          }
      }

    } catch (error) {
      addLog(`Error: ${error}`);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Badge variant="outline" className="text-primary border-primary px-3 py-1 text-lg">
            v2.0
          </Badge>
          Shannon AI Pentester
        </h1>
        <p className="text-muted-foreground">
          Autonomous Artificial Intelligence for Offensive Security Operations.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Controls & Target */}
        <Card className="lg:col-span-1 h-fit">
          <CardHeader>
            <CardTitle>Mission Control</CardTitle>
            <CardDescription>Configure the agent's parameters.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Target URL / IP</label>
              <Input 
                placeholder="https://example.com" 
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
              />
            </div>

            <div className="flex gap-2">
              <Button 
                className="w-full" 
                onClick={startAudit} 
                disabled={isScanning || !target}
                variant={isScanning ? "secondary" : "default"}
              >
                {isScanning ? (
                    <>
                        <span className="animate-pulse mr-2">●</span> Scanning...
                    </>
                ) : (
                    <>
                        <Play className="w-4 h-4 mr-2" /> Start Audit
                    </>
                )}
              </Button>
              {isScanning && (
                  <Button variant="destructive" onClick={() => setIsScanning(false)}>
                      <Square className="w-4 h-4" />
                  </Button>
              )}
            </div>
            
            <div className="bg-muted/50 p-4 rounded-lg text-xs space-y-2 border border-border">
                <div className="flex justify-between">
                    <span>Agent Status:</span>
                    <span className={isScanning ? "text-green-500" : "text-muted-foreground"}>
                        {isScanning ? "Active" : "Standby"}
                    </span>
                </div>
                <div className="flex justify-between">
                    <span>Keys Loaded:</span>
                    <span className="text-green-500">2 (Rotary)</span>
                </div>
                <div className="flex justify-between">
                    <span>Mode:</span>
                    <span className="text-orange-500">Aggressive</span>
                </div>
            </div>
          </CardContent>
        </Card>

        {/* Right: Terminal & Results */}
        <div className="lg:col-span-2 space-y-6">
            {/* Terminal Log */}
            <Card className="bg-black text-green-400 border-zinc-800 font-mono">
                <CardHeader className="py-3 border-b border-zinc-800 flex flex-row items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Terminal className="w-4 h-4" />
                        <span className="text-sm">Agent Terminal</span>
                    </div>
                    <div className="flex gap-1.5">
                        <div className="w-3 h-3 rounded-full bg-red-500/20" />
                        <div className="w-3 h-3 rounded-full bg-yellow-500/20" />
                        <div className="w-3 h-3 rounded-full bg-green-500/20" />
                    </div>
                </CardHeader>
                <CardContent className="p-0">
                    <ScrollArea className="h-[300px] p-4">
                        {logs.length === 0 && <span className="text-zinc-600 opacity-50">Waiting for command...</span>}
                        {logs.map((log, i) => (
                            <div key={i} className="mb-1 text-sm break-all">
                                <span className="text-zinc-500 mr-2">$</span>
                                {log}
                            </div>
                        ))}
                    </ScrollArea>
                </CardContent>
            </Card>

            {/* Findings */}
            {findings.length > 0 && (
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Shield className="w-5 h-5 text-red-500" />
                            Identified Vectors
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        {findings.map((finding, i) => (
                            <div key={i} className="flex items-start justify-between p-4 rounded-lg border border-border bg-card/50">
                                <div>
                                    <h4 className="font-bold flex items-center gap-2">
                                        {finding.name}
                                        <Badge variant="secondary">{finding.likelihood}</Badge>
                                    </h4>
                                    <p className="text-sm text-muted-foreground mt-1">
                                        {finding.reasoning}
                                    </p>
                                    {finding.poc_payload && (
                                        <div className="mt-3 bg-muted p-2 rounded text-xs font-mono break-all">
                                            {finding.poc_payload}
                                        </div>
                                    )}
                                </div>
                                <Button size="sm" variant="outline">
                                    Exploit
                                </Button>
                            </div>
                        ))}
                    </CardContent>
                </Card>
            )}
        </div>
      </div>
    </div>
  );
}
