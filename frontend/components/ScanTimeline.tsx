"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
// import { LockedFeature, PaidBadge } from "@/components/LockedFeature"; // Removed
import { type Scan } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  ReferenceLine
} from "recharts";
import { History, TrendingUp, TrendingDown, Minus } from "lucide-react";

interface ScanTimelineProps {
  scans: Scan[];
}

export function ScanTimeline({ scans }: ScanTimelineProps) {
  // Process data for chart
  const data = [...scans]
    .filter(s => s.status === "completed" && s.overall_score !== null)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    .map(s => ({
      date: new Date(s.created_at).toLocaleDateString(),
      fullDate: formatDate(s.created_at),
      score: s.overall_score,
      grade: s.grade,
      id: s.id,
      domain: s.domain
    }));

  // Calculate trend
  let trend: "up" | "down" | "flat" | null = null;
  if (data.length >= 2) {
    const last = data[data.length - 1].score || 0;
    const prev = data[data.length - 2].score || 0;
    if (last > prev) trend = "up";
    else if (last < prev) trend = "down";
    else trend = "flat";
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <History className="w-5 h-5 text-primary" />
              Security Score Timeline
            </span>
            <div className="flex items-center gap-4">
              {trend && (
                <div className={`flex items-center gap-1 text-sm font-medium ${
                  trend === "up" ? "text-green-500" : trend === "down" ? "text-red-500" : "text-muted-foreground"
                }`}>
                  {trend === "up" && <TrendingUp className="w-4 h-4" />}
                  {trend === "down" && <TrendingDown className="w-4 h-4" />}
                  {trend === "flat" && <Minus className="w-4 h-4" />}
                  {trend === "up" ? "Improving" : trend === "down" ? "Declining" : "Stable"}
                </div>
              )}
              {/* <PaidBadge /> */}
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[300px] w-full">
            {data.length > 1 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" opacity={0.2} />
                  <XAxis 
                    dataKey="date" 
                    stroke="#888" 
                    fontSize={12} 
                    tickLine={false} 
                    axisLine={false} 
                  />
                  <YAxis 
                    stroke="#888" 
                    fontSize={12} 
                    tickLine={false} 
                    axisLine={false} 
                    domain={[0, 100]} 
                  />
                  <Tooltip
                    content={({ active, payload, label }) => {
                      if (active && payload && payload.length) {
                        const item = payload[0].payload;
                        return (
                          <div className="bg-popover border border-border p-3 rounded-lg shadow-lg">
                            <p className="font-medium text-popover-foreground mb-1">{item.domain}</p>
                            <p className="text-sm text-muted-foreground mb-2">{item.fullDate}</p>
                            <div className="flex items-center gap-2">
                              <div className={`w-2 h-2 rounded-full ${
                                item.grade === 'A' ? 'bg-green-500' : 
                                item.grade === 'B' ? 'bg-blue-500' :
                                item.grade === 'C' ? 'bg-yellow-500' : 'bg-red-500'
                              }`} />
                              <span className="font-bold">Score: {item.score} ({item.grade})</span>
                            </div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <ReferenceLine y={90} stroke="#22c55e" strokeDasharray="3 3" opacity={0.5} />
                  <ReferenceLine y={70} stroke="#eab308" strokeDasharray="3 3" opacity={0.5} />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#10b981"
                    strokeWidth={2}
                    dot={{ fill: "#10b981", strokeWidth: 2 }}
                    activeDot={{ r: 6, fill: "#fff" }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                Not enough history data to display timeline
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </>
  );
}
