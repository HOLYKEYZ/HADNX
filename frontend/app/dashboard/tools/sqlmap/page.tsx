"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Play, Database, AlertOctagon, Terminal, CheckCircle } from "lucide-react";
import { api } from "@/lib/api";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

export default function SQLMapPage() {
  const [url, setUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<{message: string, details?: string} | null>(null);
  const [output, setOutput] = useState<{stdout: string, stderr: string} | null>(null);
  const [isVulnerable, setIsVulnerable] = useState(false);

  const handleScan = async () => {
    if (!url) return;
    setIsLoading(true);
    setError(null);
    setOutput(null);
    setIsVulnerable(false);

    try {
        const res = await api.runSQLMapScan(url);
        if (res.error) {
            setError({ message: res.error, details: res.details });
        } else {
            setOutput({ stdout: res.stdout || "", stderr: res.stderr || "" });
            if (res.vulnerable) setIsVulnerable(true);
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
                <Database className="w-6 h-6 text-red-500" /> 
                SQLMap Exploiter
            </h2>
            <p className="text-sm text-muted-foreground">Automated SQL Injection detection and exploitation.</p>
        </div>
      </div>

      {/* Input */}
      <Card className="border-border bg-black/20">
        <CardContent className="p-4 flex gap-4 items-end">
            <div className="flex-1 space-y-2">
                <label className="text-sm font-medium">Target URL (with parameters)</label>
                <Input 
                    value={url} 
                    onChange={(e) => setUrl(e.target.value)} 
                    placeholder="https://example.com/item.php?id=1" 
                    className="font-mono bg-black/50"
                />
            </div>
            <Button onClick={handleScan} disabled={isLoading} className="bg-red-600 hover:bg-red-700 w-32 mb-0.5">
                {isLoading ? <span className="animate-spin mr-2">⏳</span> : <Play className="w-4 h-4 mr-2 fill-current" />}
                Exploit
            </Button>
        </CardContent>
      </Card>

      {/* Results */}
      <Card className="flex-1 flex flex-col min-h-0 border-border bg-black">
        <CardHeader className="py-3 px-4 border-b border-border bg-muted/10 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-muted-foreground">
                <Terminal className="w-4 h-4" /> SQLMap Output
            </CardTitle>
            {isVulnerable && (
                <div className="flex items-center gap-2 text-red-500 font-bold animate-pulse text-sm">
                    <AlertOctagon className="w-4 h-4" /> VULNERABLE
                </div>
            )}
        </CardHeader>
        <div className="flex-1 p-4 font-mono text-xs overflow-auto">
            {error && <div className="text-destructive mb-2 font-bold">Error: {error.message}</div>}
            {error?.details && <pre className="text-destructive/70 mb-4 whitespace-pre-wrap">{error.details}</pre>}
            
            {output ? (
                <>
                    {output.stdout && <div className="text-gray-300 whitespace-pre-wrap">{output.stdout}</div>}
                    {output.stderr && <div className="text-red-400 whitespace-pre-wrap mt-2">{output.stderr}</div>}
                </>
            ) : (
                <div className="text-muted-foreground opacity-50">Waiting for scan...</div>
            )}
        </div>
      </Card>

      {/* Help Section */}
      <Card className="border-border">
            <Accordion type="single" collapsible>
                <AccordionItem value="help" className="border-b-0">
                    <AccordionTrigger className="px-4 py-3 text-sm font-medium hover:no-underline">
                        <span className="flex items-center gap-2"><CheckCircle className="w-4 h-4" /> How to Use SQLMap</span>
                    </AccordionTrigger>
                    <AccordionContent className="px-4 pb-4 text-sm text-muted-foreground space-y-2">
                        <p><strong>Target:</strong> You MUST provide parameters to test. (e.g. <code>http://test.com/index.php?id=1</code>).</p>
                        <p><strong>Process:</strong> The backend runs <code>sqlmap --batch --smart --dbs --random-agent</code>.</p>
                        <p><strong>Output:</strong> The raw console output is streamed here. Look for "Parameter: id (GET)... Type: boolean-based blind" or similar success messages.</p>
                    </AccordionContent>
                </AccordionItem>
            </Accordion>
      </Card>
    </div>
  );
}
