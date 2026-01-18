"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, type Scan } from "@/lib/api";
import { HistoryChart } from "@/components/charts/HistoryChart";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/utils";
import { ArrowRight, Loader2, ShieldAlert } from "lucide-react";

export default function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const loadScans = async () => {
      try {
        const data = await api.getScans();
        setScans(data);
      } catch (error) {
        console.error("Failed to load scans", error);
      } finally {
        setIsLoading(false);
      }
    };

    loadScans();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "default"; // Black/Primary
      case "failed":
        return "destructive";
      case "running":
        return "secondary";
      default:
        return "outline";
    }
  };

  const getGradeColor = (grade: string) => {
    if (!grade) return "bg-gray-100 text-gray-800";
    if (grade.startsWith("A")) return "bg-green-100 text-green-800 border-green-200";
    if (grade.startsWith("B")) return "bg-blue-100 text-blue-800 border-blue-200";
    if (grade.startsWith("C")) return "bg-yellow-100 text-yellow-800 border-yellow-200";
    return "bg-red-100 text-red-800 border-red-200";
  };

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Scan History</h1>
        <p className="text-muted-foreground">Track your security posture over time.</p>
      </div>

      <div className="grid gap-6">
        <HistoryChart scans={scans} />

        <Card>
            <CardHeader>
                <CardTitle>Recent Scans</CardTitle>
                <CardDescription>
                    A list of all security assessments performed.
                </CardDescription>
            </CardHeader>
            <CardContent>
                {scans.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                        <ShieldAlert className="h-12 w-12 mx-auto mb-3 opacity-20" />
                        <p>No scans found. Start a new scan to see history.</p>
                        <Button asChild className="mt-4" variant="outline">
                            <Link href="/dashboard">Start Scan</Link>
                        </Button>
                    </div>
                ) : (
                    <Table>
                    <TableHeader>
                        <TableRow>
                        <TableHead>Target</TableHead>
                        <TableHead>Date</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Grade</TableHead>
                        <TableHead>Score</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {scans.map((scan) => (
                        <TableRow key={scan.id}>
                            <TableCell className="font-medium">{scan.domain}</TableCell>
                            <TableCell>{formatDate(scan.created_at)}</TableCell>
                            <TableCell>
                            <Badge variant={getStatusColor(scan.status) as any}>
                                {scan.status}
                            </Badge>
                            </TableCell>
                            <TableCell>
                                {scan.grade && (
                                    <span className={`px-2 py-1 rounded text-xs font-bold border ${getGradeColor(scan.grade)}`}>
                                        {scan.grade}
                                    </span>
                                )}
                            </TableCell>
                            <TableCell>
                                {scan.overall_score !== null ? (
                                    <span className="font-mono font-medium">{scan.overall_score}/100</span>
                                ) : (
                                    <span className="text-muted-foreground">-</span>
                                )}
                            </TableCell>
                            <TableCell className="text-right">
                            <Button variant="ghost" size="sm" asChild>
                                <Link href={`/dashboard/report/${scan.id}`}>
                                View <ArrowRight className="ml-2 h-4 w-4" />
                                </Link>
                            </Button>
                            </TableCell>
                        </TableRow>
                        ))}
                    </TableBody>
                    </Table>
                )}
            </CardContent>
        </Card>
      </div>
    </div>
  );
}
