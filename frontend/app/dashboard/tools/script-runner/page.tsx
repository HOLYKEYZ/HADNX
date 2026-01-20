"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Play, Terminal, AlertTriangle, Code, HelpCircle } from "lucide-react";
import { api } from "@/lib/api";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

const DEFAULT_SCRIPT = `# Python Script Runner
# You can use 'requests', 're', 'json', etc.
import requests
import json

target = "https://example.com"
print(f"[*] Scanning {target}...")

try:
    resp = requests.get(target, timeout=5)
    print(f"[+] Status: {resp.status_code}")
    print(f"[+] Headers: {json.dumps(dict(resp.headers), indent=2)}")
except Exception as e:
    print(f"[-] Error: {e}")
`;

export default function ScriptRunnerPage() {
  const [script, setScript] = useState(DEFAULT_SCRIPT);
  const [output, setOutput] = useState<{stdout: string, stderr: string} | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const handleRun = async () => {
    setIsLoading(true);
    setError("");
    setOutput(null);
    
    try {
        const res = await api.runScript(script);
        setOutput({ stdout: res.stdout || "", stderr: res.stderr || "" });
        if (res.error) setError(res.error);
    } catch (err: any) {
        setError(err.error || "Execution failed");
    } finally {
        setIsLoading(false);
    }
  };

  return (
    <div className="h-[calc(100vh-6rem)] flex flex-col gap-4">
      {/* Header & Controls */}
      <div className="flex items-center justify-between p-2 bg-muted/30 border border-border rounded-lg">
        <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-primary" />
            <h2 className="font-bold">Python Script Runner</h2>
        </div>
        <Button onClick={handleRun} disabled={isLoading} className="gap-2 bg-green-600 hover:bg-green-700 text-white w-32">
            {isLoading ? <span className="animate-spin">⏳</span> : <Play className="w-4 h-4 fill-current" />}
            Run
        </Button>
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-4 min-h-0">
        {/* Editor */}
        <Card className="flex flex-col min-h-0 border-border bg-black/20">
            <CardHeader className="py-3 px-4 border-b border-border bg-muted/20">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Code className="w-4 h-4" /> Code Editor
                </CardTitle>
            </CardHeader>
            <div className="flex-1 p-0 relative">
                <Textarea 
                    value={script} 
                    onChange={(e) => setScript(e.target.value)} 
                    className="absolute inset-0 w-full h-full resize-none font-mono text-xs bg-[#1e1e1e] text-[#d4d4d4] border-0 focus-visible:ring-0 p-4 leading-normal" 
                    spellCheck={false}
                />
            </div>
        </Card>

        {/* Output & Help */}
        <div className="flex flex-col gap-4 min-h-0">
            {/* Console Output */}
            <Card className="flex-1 flex flex-col min-h-0 border-border bg-black">
                <CardHeader className="py-3 px-4 border-b border-border bg-muted/10">
                    <CardTitle className="text-sm font-medium flex items-center gap-2 text-muted-foreground">
                        <Terminal className="w-4 h-4" /> Console Output
                    </CardTitle>
                </CardHeader>
                <div className="flex-1 p-4 font-mono text-xs overflow-auto">
                    {error && <div className="text-destructive mb-2 font-bold">Error: {error}</div>}
                    {output ? (
                        <>
                            {output.stdout && <div className="text-green-400 whitespace-pre-wrap">{output.stdout}</div>}
                            {output.stderr && <div className="text-red-400 whitespace-pre-wrap mt-2">{output.stderr}</div>}
                            {!output.stdout && !output.stderr && <div className="text-muted-foreground italic">Script finished with no output.</div>}
                        </>
                    ) : (
                        <div className="text-muted-foreground opacity-50">Waiting for execution...</div>
                    )}
                </div>
            </Card>

            {/* How to Use */}
            <Card className="border-border">
                <Accordion type="single" collapsible>
                    <AccordionItem value="help" className="border-b-0">
                        <AccordionTrigger className="px-4 py-3 text-sm font-medium hover:no-underline">
                            <span className="flex items-center gap-2"><HelpCircle className="w-4 h-4" /> How to Use & Examples</span>
                        </AccordionTrigger>
                        <AccordionContent className="px-4 pb-4 text-sm text-muted-foreground space-y-2">
                            <p>This environment runs <strong>Python 3</strong> on the server. You have access to standard libraries and <code>requests</code>.</p>
                            <div className="bg-muted/50 p-2 rounded border border-border">
                                <p className="font-semibold text-xs mb-1">Available Modules:</p>
                                <code className="text-xs">requests, json, re, time, urllib, base64, hashlib</code>
                            </div>
                            <div className="p-2 border border-destructive/20 bg-destructive/10 rounded text-destructive text-xs flex items-start gap-2">
                                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                                <span><strong>Warning:</strong> Scripts run on the backend server. Do not execute untrusted code. Network access is allowed for scanning targets.</span>
                            </div>
                        </AccordionContent>
                    </AccordionItem>
                </Accordion>
            </Card>
        </div>
      </div>
    </div>
  );
}
