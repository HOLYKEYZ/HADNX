
"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Activity, Flame, ShieldAlert, StopCircle } from "lucide-react";

export default function DoSPage() {
  const [target, setTarget] = useState("");
  const [method, setMethod] = useState("HTTP");
  const [intensity, setIntensity] = useState("medium");
  const [isRunning, setIsRunning] = useState(false);

  const startAttack = async () => {
    setIsRunning(true);
    try {
        await fetch("/api/scans/dos/start/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target, method, intensity, duration: 60 })
        });
    } catch (e) {
        console.error(e);
        setIsRunning(false);
    }
  };

  const stopAttack = async () => {
      try {
          await fetch("/api/scans/dos/stop/", { method: "POST" });
      } finally {
          setIsRunning(false);
      }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold flex items-center gap-3 text-red-500">
          <Flame className="w-8 h-8" />
          DoS Simulator
        </h1>
        <p className="text-muted-foreground">
          Stress test your infrastructure handling capacity. Authorized use only.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <Card className="md:col-span-1">
            <CardHeader>
                <CardTitle>Configuration</CardTitle>
                <CardDescription>Set attack parameters.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                <div className="space-y-2">
                    <label className="text-sm font-medium">Target URL</label>
                    <Input 
                        placeholder="http://test.local" 
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                    />
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Method</label>
                        <Select value={method} onValueChange={setMethod}>
                            <SelectTrigger>
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="HTTP">HTTP Flood</SelectItem>
                                <SelectItem value="SLOWLORIS">Slowloris</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Intensity</label>
                        <Select value={intensity} onValueChange={setIntensity}>
                            <SelectTrigger>
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="low">Low (10 Threads)</SelectItem>
                                <SelectItem value="medium">Medium (50 Threads)</SelectItem>
                                <SelectItem value="high">High (100 Threads)</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                </div>

                <div className="pt-4">
                    {!isRunning ? (
                        <Button className="w-full bg-red-600 hover:bg-red-700" onClick={startAttack} disabled={!target}>
                            <Activity className="w-4 h-4 mr-2" /> Start Simulation
                        </Button>
                    ) : (
                        <Button className="w-full" variant="secondary" onClick={stopAttack}>
                            <StopCircle className="w-4 h-4 mr-2" /> Stop Simulation
                        </Button>
                    )}
                </div>
            </CardContent>
        </Card>

        {/* Live Status Visualization (Mock) */}
        <Card className="md:col-span-1 bg-zinc-950 text-white border-zinc-800">
            <CardHeader>
                <CardTitle className="flex justify-between items-center">
                    <span>Live Metrics</span>
                    {isRunning && <Badge className="bg-red-500 animate-pulse">LIVE</Badge>}
                </CardTitle>
            </CardHeader>
            <CardContent className="h-[300px] flex items-center justify-center relative overflow-hidden">
                {isRunning ? (
                    <div className="w-full h-full flex flex-col items-center justify-center space-y-4 z-10">
                        <div className="text-6xl font-black text-red-500 tabular-nums tracking-tighter">
                            {intensity === 'high' ? '4,502' : intensity === 'medium' ? '1,240' : '230'}
                        </div>
                        <div className="text-sm text-zinc-400 uppercase tracking-widest font-medium">Req / Second</div>
                        
                        <div className="w-full px-8 mt-8 space-y-2">
                            <div className="flex justify-between text-xs text-zinc-500">
                                <span>Bandwidth</span>
                                <span>12.4 MB/s</span>
                            </div>
                            <div className="w-full bg-zinc-900 h-1.5 rounded-full overflow-hidden">
                                <div className="h-full bg-red-500 w-[60%] animate-pulse" />
                            </div>
                            
                            <div className="flex justify-between text-xs text-zinc-500 mt-2">
                                <span>Error Rate</span>
                                <span>0.2%</span>
                            </div>
                            <div className="w-full bg-zinc-900 h-1.5 rounded-full overflow-hidden">
                                <div className="h-full bg-orange-500 w-[5%]" />
                            </div>
                        </div>
                    </div>
                ) : (
                    <div className="text-zinc-700 flex flex-col items-center">
                        <Activity className="w-16 h-16 mb-2 opacity-20" />
                        <span>Ready to simulate</span>
                    </div>
                )}
                
                {/* Background Effect */}
                {isRunning && (
                    <div className="absolute inset-0 bg-red-900/10 animate-pulse pointer-events-none" />
                )}
            </CardContent>
        </Card>
      </div>
    </div>
  );
}
