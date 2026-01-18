"use client";

import { Scan } from "@/lib/api";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDate } from "@/lib/utils";

interface HistoryChartProps {
  scans: Scan[];
}

export function HistoryChart({ scans }: HistoryChartProps) {
  // Sort scans by date (oldest first) for the chart
  const data = [...scans]
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    .map((scan) => ({
      date: new Date(scan.created_at).toLocaleDateString(),
      score: scan.overall_score || 0,
      domain: scan.domain,
    }));

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Security Trend</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[300px] flex items-center justify-center text-muted-foreground">
            No scan data available.
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Security Score Trend</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[300px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={data}
              margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted/30" />
              <XAxis 
                dataKey="date" 
                className="text-xs text-muted-foreground" 
                tick={{ fill: 'currentColor' }}
              />
              <YAxis 
                domain={[0, 100]} 
                className="text-xs text-muted-foreground"
                tick={{ fill: 'currentColor' }} 
              />
              <Tooltip
                content={({ active, payload, label }) => {
                  if (active && payload && payload.length) {
                    return (
                      <div className="bg-background border border-border p-2 rounded shadow-lg text-sm">
                        <p className="font-medium">{label}</p>
                        <p className="text-primary font-bold">
                          Score: {payload[0].value}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {payload[0].payload.domain}
                        </p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Line
                type="monotone"
                dataKey="score"
                stroke="hsl(var(--primary))"
                strokeWidth={2}
                dot={{ r: 4, fill: "hsl(var(--background))", strokeWidth: 2 }}
                activeDot={{ r: 6, fill: "hsl(var(--primary))" }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
