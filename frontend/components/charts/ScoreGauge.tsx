"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { cn } from "@/lib/utils";

interface ScoreGaugeProps {
  score: number;
  grade: string;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
}

export function ScoreGauge({ score, grade, size = "md", showLabel = true }: ScoreGaugeProps) {
  const getGradeColor = (grade: string): string => {
    const colors: Record<string, string> = {
      "A+": "#10b981",
      A: "#22c55e",
      B: "#84cc16",
      C: "#eab308",
      D: "#f97316",
      F: "#ef4444",
    };
    return colors[grade] || "#6b7280";
  };

  const color = getGradeColor(grade);
  const remaining = 100 - score;

  const data = [
    { name: "score", value: score },
    { name: "remaining", value: remaining },
  ];

  const sizes = {
    sm: { width: 100, height: 100, fontSize: "text-xl", gradeSize: "text-xs" },
    md: { width: 160, height: 160, fontSize: "text-3xl", gradeSize: "text-sm" },
    lg: { width: 220, height: 220, fontSize: "text-5xl", gradeSize: "text-lg" },
  };

  const { width, height, fontSize, gradeSize } = sizes[size];

  return (
    <div className="relative" style={{ width, height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={size === "lg" ? 75 : size === "md" ? 55 : 35}
            outerRadius={size === "lg" ? 95 : size === "md" ? 70 : 45}
            startAngle={90}
            endAngle={-270}
            dataKey="value"
            stroke="none"
          >
            <Cell fill={color} />
            <Cell fill="#262626" />
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      {showLabel && (
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("font-bold", fontSize)} style={{ color }}>
            {score}
          </span>
          <span className={cn("text-muted-foreground font-medium", gradeSize)}>
            {grade}
          </span>
        </div>
      )}
    </div>
  );
}
