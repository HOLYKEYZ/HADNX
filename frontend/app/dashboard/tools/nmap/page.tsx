"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Play, Network, Globe, Activity, HelpCircle } from "lucide-react";
import { api } from "@/lib/api";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

export default function NmapPage() {
  const [target, setTarget] = useState("");
  const [ports, setPorts] = useState("1-1000");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<{message: string, details?: string} | null>(null);
  const [results, setResults] = useState<any[]>([]);
  const [ranScan, setRanScan] = useState(false);

  const handleScan = async () => {
    if (!target) return;
    setIsLoading(true);
    setError(null);
    setResults([]);
    setRanScan(false);

    try {
        const res = await api.runNmapScan(target, ports);
        if (res.error) {
            setError({ message: res.error, details: res.details });
        } else {
            setResults(res.results || []);
            setRanScan(true);
        }
    } catch (err: any) {
        setError({ message: err.error || "Scan failed", details: err.details });
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
                <Network className="w-6 h-6 text-blue-500" /> 
                Nmap Network Scanner
            </h2>
            <p className="text-sm text-muted-foreground">Port scanning and service detection.</p>
        </div>
      </div>

      {/* Input */}
      <Card className="border-border bg-black/20">
        <CardContent className="p-4 flex gap-4 items-end">
            <div className="flex-1 space-y-2">
                <label className="text-sm font-medium">Target IP / Domain</label>
                <Input 
                    value={target} 
                    onChange={(e) => setTarget(e.target.value)} 
                    placeholder="192.168.1.1 or example.com" 
                    className="font-mono bg-black/50"
                />
            </div>
            <div className="w-32 space-y-2">
                <label className="text-sm font-medium">Ports</label>
                <Input 
                    value={ports} 
                    onChange={(e) => setPorts(e.target.value)} 
                    placeholder="1-1000" 
                    className="font-mono bg-black/50"
                />
            </div>
            <Button onClick={handleScan} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 w-32 mb-0.5">
                {isLoading ? <span className="animate-spin mr-2">⏳</span> : <Play className="w-4 h-4 mr-2 fill-current" />}
                Scan
            </Button>
        </CardContent>
      </Card>

      {/* Results */}
      <div className="flex-1 min-h-0 overflow-auto space-y-4">
        {error && (
            <div className="p-4 border border-destructive/50 bg-destructive/10 rounded-lg text-destructive">
                <div className="font-bold flex items-center gap-2">
                    <Activity className="w-5 h-5" />
                    {error.message}
                </div>
                {error.details && <pre className="mt-2 text-xs opacity-80 whitespace-pre-wrap">{error.details}</pre>}
            </div>
        )}

        {ranScan && results.length === 0 && !error && (
            <div className="p-8 text-center text-muted-foreground border border-dashed border-border rounded-lg">
                <Globe className="w-8 h-8 mx-auto mb-2 text-blue-500" />
                No up hosts found or ports closed.
            </div>
        )}

        {results.map((host, i) => (
            <Card key={i} className="border-border bg-black/10">
                <CardHeader className="py-2 px-4 border-b border-border bg-muted/10">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                        <Globe className="w-4 h-4 text-blue-400" />
                        {host.host} <span className="text-muted-foreground ml-auto uppercase text-xs border border-border px-2 rounded">{host.state}</span>
                    </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                    {host.protocols.map((proto: any, j: number) => (
                        <div key={j} className="p-4">
                            <h4 className="text-xs font-bold text-muted-foreground uppercase mb-2">{proto.protocol} Protocol</h4>
                            <div className="space-y-1">
                                {proto.ports.map((port: any, k: number) => (
                                    <div key={k} className="flex items-center text-sm font-mono p-1 hover:bg-white/5 rounded">
                                        <span className="w-16 text-blue-400 font-bold">{port.port}</span>
                                        <span className={`w-20 uppercase text-xs font-semibold ${port.state === 'open' ? 'text-green-500' : 'text-yellow-500'}`}>{port.state}</span>
                                        <span className="flex-1 text-gray-300">{port.name} {port.product && <span className="text-muted-foreground">({port.product} {port.version})</span>}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </CardContent>
            </Card>
        ))}
      </div>
      
      {/* Help Section */}
      <Card className="border-border">
            <Accordion type="single" collapsible>
                <AccordionItem value="help" className="border-b-0">
                    <AccordionTrigger className="px-4 py-3 text-sm font-medium hover:no-underline">
                        <span className="flex items-center gap-2"><HelpCircle className="w-4 h-4" /> How to Use Nmap</span>
                    </AccordionTrigger>
                    <AccordionContent className="px-4 pb-4 text-sm text-muted-foreground space-y-2">
                        <p><strong>Target:</strong> Enter an IP address (e.g., <code>127.0.0.1</code>) or domain.</p>
                        <p><strong>Ports:</strong> Specify a range (<code>1-1000</code>), single port (<code>80</code>), or list (<code>80,443,8080</code>).</p>
                        <p>This tool runs a service detection scan (<code>-sV</code>) which identifies software versions running on open ports.</p>
                    </AccordionContent>
                </AccordionItem>
            </Accordion>
      </Card>
    </div>
  );
}
