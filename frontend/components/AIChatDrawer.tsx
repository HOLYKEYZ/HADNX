"use client";

import { useState, useRef, useEffect } from "react";
import { Send, Bot, User as UserIcon, Loader2, X, Terminal, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card";
import ReactMarkdown from "react-markdown";
import { api } from "@/lib/api";

interface Message {
  role: "user" | "model";
  content: string;
}

interface AIChatDrawerProps {
  scanId: string;
  isOpen: boolean;
  onClose: () => void;
  initialMessage?: string;
}

export function AIChatDrawer({ scanId, isOpen, onClose, initialMessage }: AIChatDrawerProps) {
  const [messages, setMessages] = useState<Message[]>([
    { role: "model", content: "Hi! I'm your AI Security Assistant. I can explain findings, write exploit scripts, or help you fix vulnerabilities. Ask me anything about this scan!" }
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  
  // Load history on open
  useEffect(() => {
    if (isOpen) {
        setIsLoading(true);
        api.getChatHistory(scanId)
            .then(data => {
                if (Array.isArray(data) && data.length > 0) {
                    setMessages(data);
                }
            })
            .catch(err => console.error("Failed to load chat history", err))
            .finally(() => setIsLoading(false));
    }
  }, [isOpen, scanId]);

  // Handle initial prompt from "Ask AI" buttons
  useEffect(() => {
    if (isOpen && initialMessage) {
        setInput(initialMessage);
        // Optional: auto-send could go here if undesired behavior isn't triggered
    }
  }, [isOpen, initialMessage]);

  useEffect(() => {
    if (scrollRef.current) {
        scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isOpen]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMsg: Message = { role: "user", content: input };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const response = await api.sendMessageToAI(scanId, userMsg.content);
      
      if (response.error) {
        setMessages(prev => [...prev, { role: "model", content: `❌ Error: ${response.error}` }]);
      } else {
        // We get back the simplified response object { content: "...", role: "model" }
        setMessages(prev => [...prev, { role: "model", content: response.content }]);
      }
    } catch (e) {
      setMessages(prev => [...prev, { role: "model", content: "❌ Failed to connect to AI service." }]);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-[450px] bg-background border-l border-border shadow-2xl z-50 flex flex-col animate-in slide-in-from-right duration-300">
      <div className="p-4 border-b border-border flex items-center justify-between bg-muted/30">
        <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-primary/10">
                <Bot className="w-5 h-5 text-primary" />
            </div>
            <div>
                <h3 className="font-semibold text-sm">Security Consultant</h3>
                <p className="text-xs text-muted-foreground flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                    Online • Gemini 2.5 Flash
                </p>
            </div>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
            <X className="w-4 h-4" />
        </Button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4" ref={scrollRef}>
        {messages.map((m, i) => (
            <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${m.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}`}>
                    {m.role === 'user' ? <UserIcon className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                </div>
                <div className={`rounded-lg p-3 max-w-[85%] text-sm ${m.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-card border border-border'}`}>
                    {m.role === 'user' ? (
                        <p>{m.content}</p>
                    ) : (
                        <div className="prose prose-sm dark:prose-invert max-w-none">
                            <ReactMarkdown
                                components={{
                                    code({node, inline, className, children, ...props}: any) {
                                        const match = /language-(\w+)/.exec(className || '')
                                        return !inline ? (
                                            <div className="relative group my-2">
                                                <div className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                                    <Button variant="secondary" size="icon" className="h-6 w-6" onClick={() => navigator.clipboard.writeText(String(children))}>
                                                        <Copy className="w-3 h-3" />
                                                    </Button>
                                                </div>
                                                <pre className="bg-black/50 p-3 rounded-md overflow-x-auto text-xs font-mono border border-border">
                                                    <code className={className} {...props}>
                                                        {children}
                                                    </code>
                                                </pre>
                                            </div>
                                        ) : (
                                            <code className="bg-muted px-1 py-0.5 rounded font-mono text-xs" {...props}>
                                                {children}
                                            </code>
                                        )
                                    }
                                }}
                            >
                                {m.content}
                            </ReactMarkdown>
                        </div>
                    )}
                </div>
            </div>
        ))}
        {isLoading && (
            <div className="flex gap-3">
                <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center">
                    <Bot className="w-4 h-4" />
                </div>
                <div className="bg-card border border-border rounded-lg p-3 flex items-center gap-2">
                    <Loader2 className="w-4 h-4 animate-spin text-primary" />
                    <span className="text-xs text-muted-foreground">Thinking...</span>
                </div>
            </div>
        )}
      </div>

      <div className="p-4 border-t border-border bg-background">
        <form 
            onSubmit={(e) => { e.preventDefault(); handleSend(); }}
            className="flex gap-2"
        >
            <Input 
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask how to exploit this..."
                disabled={isLoading}
                className="flex-1"
            />
            <Button type="submit" disabled={isLoading || !input.trim()}>
                <Send className="w-4 h-4" />
            </Button>
        </form>
        <p className="text-[10px] text-muted-foreground text-center mt-2">
            AI can make mistakes. Verify exploits in a safe environment.
        </p>
      </div>
    </div>
  );
}
