"use client";

import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, LabelList } from "recharts";

interface CategoryScoresProps {
  scores: {
    headers: number | null;
    cookies: number | null;
    tls: number | null;
    https: number | null;
  };
}

export function CategoryScores({ scores }: CategoryScoresProps) {
  const getColor = (score: number | null): string => {
    if (score === null) return "#6b7280";
    if (score >= 80) return "#10b981";
    if (score >= 60) return "#eab308";
    if (score >= 40) return "#f97316";
    return "#ef4444";
  };

  const data = [
    { name: "Headers", score: scores.headers ?? 0, label: "HTTP Headers" },
    { name: "Cookies", score: scores.cookies ?? 0, label: "Cookies" },
    { name: "TLS", score: scores.tls ?? 0, label: "TLS/SSL" },
    { name: "HTTPS", score: scores.https ?? 0, label: "HTTPS" },
  ];

  return (
    <div className="w-full h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 20, right: 20, bottom: 5, left: 10 }}>
          <XAxis
            dataKey="name"
            axisLine={false}
            tickLine={false}
            tick={{ fill: "#a3a3a3", fontSize: 12 }}
          />
          <YAxis
            domain={[0, 100]}
            axisLine={false}
            tickLine={false}
            tick={{ fill: "#a3a3a3", fontSize: 12 }}
          />
          <Bar dataKey="score" radius={[4, 4, 0, 0]} maxBarSize={50}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={getColor(entry.score)} />
            ))}
            <LabelList
              dataKey="score"
              position="top"
              formatter={(value: number) => `${value}`}
              style={{ fill: "#fafafa", fontSize: 12, fontWeight: 600 }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
