"use client";

import { useState } from "react";
import { ChevronDown, ChevronUp, Copy, Check } from "lucide-react";
import { cn } from "@/lib/utils";

interface FixPanelProps {
  fixExamples: Record<string, string>;
}

export function FixPanel({ fixExamples }: FixPanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const frameworks = Object.keys(fixExamples);

  if (frameworks.length === 0) return null;

  const copyToClipboard = async (key: string, code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  return (
    <div className="mt-4 border border-border rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 bg-muted/50 hover:bg-muted transition-colors text-left"
      >
        <span className="text-sm font-medium text-primary">
          Fix this issue
        </span>
        {isOpen ? (
          <ChevronUp className="w-4 h-4 text-muted-foreground" />
        ) : (
          <ChevronDown className="w-4 h-4 text-muted-foreground" />
        )}
      </button>

      {isOpen && (
        <div className="p-4 space-y-4 bg-card">
          {frameworks.map((framework) => (
            <div key={framework}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium capitalize">
                  {framework}
                </span>
                <button
                  onClick={() => copyToClipboard(framework, fixExamples[framework])}
                  className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  {copiedKey === framework ? (
                    <>
                      <Check className="w-3 h-3" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      Copy
                    </>
                  )}
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-muted text-xs overflow-x-auto font-mono">
                <code>{fixExamples[framework]}</code>
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
