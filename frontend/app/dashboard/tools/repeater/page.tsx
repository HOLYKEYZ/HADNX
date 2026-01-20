"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Send, Play, Save, History, Trash2, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";

type Method = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";

export default function RepeaterPage() {
  const [method, setMethod] = useState<Method>("GET");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState("User-Agent: Hadnx/1.0\nContent-Type: application/json");
  const [body, setBody] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [response, setResponse] = useState<any>(null);
  const [error, setError] = useState("");

  const handleSend = async () => {
    if (!url) {
        setError("URL is required");
        return;
    }
    setError("");
    setIsLoading(true);
    setResponse(null);

    try {
        // Parse headers
        const headerLines = headers.split('\n');
        const headerObj: Record<string, string> = {};
        headerLines.forEach(line => {
            const [key, ...values] = line.split(':');
            if (key && values.length > 0) {
                headerObj[key.trim()] = values.join(':').trim();
            }
        });

        const data = {
            url,
            method,
            headers: headerObj,
            body: body || undefined,
            follow_redirects: true
        };

        const res = await api.sendRepeaterRequest(data);
        setResponse(res);
    } catch (err: any) {
        setError(err.error || "Request failed");
        setResponse(err); // Show partial response if available
    } finally {
        setIsLoading(false);
    }
  };

  return (
    <div className="h-[calc(100vh-6rem)] flex flex-col gap-4">
      {/* Top Bar */}
      <div className="flex items-center gap-2 p-2 bg-muted/30 border border-border rounded-lg">
        <select 
            value={method} 
            onChange={(e) => setMethod(e.target.value as Method)}
            className="bg-background border border-border rounded px-3 py-2 text-sm font-bold w-28"
        >
            {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].map(m => (
                <option key={m} value={m}>{m}</option>
            ))}
        </select>
        <Input 
            value={url} 
            onChange={(e) => setUrl(e.target.value)} 
            placeholder="https://example.com/api/v1/user"
            className="flex-1 font-mono text-sm"
        />
        <Button onClick={handleSend} disabled={isLoading} className="gap-2 bg-green-600 hover:bg-green-700 text-white w-32">
            {isLoading ? <span className="animate-spin">⏳</span> : <Play className="w-4 h-4 fill-current" />}
            Send
        </Button>
      </div>

      {/* Main Split View */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-4 min-h-0">
        
        {/* Left: Request Editor */}
        <Card className="flex flex-col min-h-0 border-border bg-black/20">
            <div className="p-2 border-b border-border bg-muted/20 flex justify-between items-center">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground ml-2">Request</span>
            </div>
            <div className="flex-1 min-h-0 p-0">
                <Tabs defaultValue="headers" className="h-full flex flex-col">
                    <TabsList className="w-full justify-start rounded-none border-b border-border bg-transparent p-0 h-9">
                        <TabsTrigger value="headers" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-4">Headers</TabsTrigger>
                        <TabsTrigger value="body" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-4">Body</TabsTrigger>
                    </TabsList>
                    <TabsContent value="headers" className="flex-1 p-0 m-0 min-h-0 relative">
                        <Textarea 
                            value={headers}
                            onChange={(e) => setHeaders(e.target.value)}
                            className="absolute inset-0 w-full h-full resize-none font-mono text-xs bg-transparent border-0 focus-visible:ring-0 p-4 leading-normal"
                            placeholder="Header-Name: Value"
                        />
                    </TabsContent>
                    <TabsContent value="body" className="flex-1 p-0 m-0 min-h-0 relative">
                        <Textarea 
                            value={body}
                            onChange={(e) => setBody(e.target.value)}
                            className="absolute inset-0 w-full h-full resize-none font-mono text-xs bg-transparent border-0 focus-visible:ring-0 p-4 leading-normal"
                            placeholder="{ 'json': 'payload' }"
                        />
                    </TabsContent>
                </Tabs>
            </div>
        </Card>

        {/* Right: Response Viewer */}
        <Card className="flex flex-col min-h-0 border-border bg-black/40">
            <div className="p-2 border-b border-border bg-muted/20 flex justify-between items-center h-[53px]">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground ml-2">Response</span>
                {response && response.headers && (
                    <div className="flex items-center gap-3 text-xs font-mono mr-2">
                        <span className={`px-2 py-0.5 rounded ${
                            response.status >= 500 ? 'bg-destructive/20 text-destructive' :
                            response.status >= 400 ? 'bg-orange-500/20 text-orange-500' :
                            response.status >= 300 ? 'bg-blue-500/20 text-blue-500' :
                            'bg-green-500/20 text-green-500'
                        }`}>
                            Status: {response.status} {response.status_text}
                        </span>
                        <span className="text-muted-foreground">{response.elapsed}ms</span>
                        <span className="text-muted-foreground">{response.headers['Content-Length'] || response.body?.length || 0} bytes</span>
                    </div>
                )}
            </div>
            
            <div className="flex-1 min-h-0 overflow-auto bg-black/60 font-mono text-xs p-4 relative">
                {error && <div className="text-destructive mb-4 p-2 border border-destructive/50 bg-destructive/10 rounded">{error}</div>}
                
                {response ? (
                    <div className="space-y-4">
                        {/* Response Headers */}
                        {response.headers && (
                            <div className="text-purple-400 border-b border-border pb-2 mb-2">
                                {Object.entries(response.headers).map(([k, v]) => (
                                    <div key={k}><span className="font-bold text-purple-300">{k}:</span> {String(v)}</div>
                                ))}
                            </div>
                        )}
                        {/* Response Body */}
                        <div className="text-gray-300 whitespace-pre-wrap break-all">
                            {response.body}
                        </div>
                    </div>
                ) : (
                    <div className="absolute inset-0 flex items-center justify-center text-muted-foreground">
                        No response yet. Send a request to see output.
                    </div>
                )}
            </div>
        </Card>
      </div>
    </div>
  );
}
