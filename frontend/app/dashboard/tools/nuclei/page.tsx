"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Play, AlertTriangle, ShieldAlert, CheckCircle, Info } from "lucide-react";
import { api } from "@/lib/api";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

export default function NucleiPage() {
  const [url, setUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<{message: string, details?: string} | null>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [ranScan, setRanScan] = useState(false);

  const handleScan = async () => {
    if (!url) return;
    setIsLoading(true);
    setError(null);
    setFindings([]);
    setRanScan(false);

    try {
        const res = await api.runNucleiScan(url);
        if (res.error) {
            setError({ message: res.error, details: res.details });
        } else {
            setFindings(res.findings || []);
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
                <ShieldAlert className="w-6 h-6 text-orange-500" /> 
                Nuclei Fast Scanner
            </h2>
            <p className="text-sm text-muted-foreground">Run template-based vulnerability scans powered by Nuclei.</p>
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
                />
            </div>
            <Button onClick={handleScan} disabled={isLoading} className="bg-orange-600 hover:bg-orange-700 w-32 mb-0.5">
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
                    <AlertTriangle className="w-5 h-5" />
                    {error.message}
                </div>
                {error.details && <pre className="mt-2 text-xs opacity-80 whitespace-pre-wrap">{error.details}</pre>}
            </div>
        )}

        {ranScan && findings.length === 0 && !error && (
            <div className="p-8 text-center text-muted-foreground border border-dashed border-border rounded-lg">
                <CheckCircle className="w-8 h-8 mx-auto mb-2 text-green-500" />
                No vulnerabilities found by Nuclei default templates.
            </div>
        )}

        {findings.map((finding, i) => (
            <Card key={i} className="border-border border-l-4 border-l-red-500 bg-black/10">
                <CardContent className="p-4">
                    <div className="flex justify-between items-start">
                        <div>
                            <h3 className="font-bold text-lg text-red-400">{finding.info?.name || finding.template_id}</h3>
                            <div className="flex items-center gap-2 text-sm text-muted-foreground mt-1">
                                <span className={`px-2 py-0.5 rounded text-xs uppercase font-bold text-white
                                    ${finding.info?.severity === 'critical' ? 'bg-red-700' :
                                      finding.info?.severity === 'high' ? 'bg-red-600' :
                                      finding.info?.severity === 'medium' ? 'bg-orange-600' :
                                      finding.info?.severity === 'low' ? 'bg-yellow-600' : 'bg-blue-600'}
                                `}>
                                    {finding.info?.severity || 'UNKNOWN'}
                                </span>
                                <span className="font-mono">{finding.type}</span>
                            </div>
                        </div>
                        <div className="text-xs text-muted-foreground font-mono">
                            {finding.curr_time}
                        </div>
                    </div>
                    
                    <div className="mt-4 p-3 bg-black/50 rounded border border-border font-mono text-xs overflow-x-auto text-gray-300">
                        <div><strong>Matched:</strong> {finding.matched_at}</div>
                        {finding.curl_command && (
                            <div className="mt-2 text-green-400">$ {finding.curl_command}</div>
                        )}
                        {finding.extracted_results && (
                            <div className="mt-2 text-yellow-400">Extracted: {finding.extracted_results.join(', ')}</div>
                        )}
                    </div>
                </CardContent>
            </Card>
        ))}
      </div>

      {/* Help Section */}
      <Card className="border-border">
            <Accordion type="single" collapsible>
                <AccordionItem value="help" className="border-b-0">
                    <AccordionTrigger className="px-4 py-3 text-sm font-medium hover:no-underline">
                        <span className="flex items-center gap-2"><Info className="w-4 h-4" /> How to Use Nuclei</span>
                    </AccordionTrigger>
                    <AccordionContent className="px-4 pb-4 text-sm text-muted-foreground space-y-2">
                        <p><strong>Target:</strong> Enter a full URL (e.g. <code>https://example.com</code> or <code>http://10.10.10.5</code>).</p>
                        <p><strong>What it does:</strong> Runs a fast, template-based scan against the target to find known CVEs, misconfigurations, and specific technology exposures.</p>
                        <p><strong>Results:</strong> Vulnerabilities are listed by severity. Critical/High findings are highlighted in red.</p>
                    </AccordionContent>
                </AccordionItem>
            </Accordion>
      </Card>
    </div>
  );
}
