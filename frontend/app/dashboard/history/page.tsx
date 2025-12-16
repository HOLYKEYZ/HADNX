"use client";

import { useEffect, useState } from "react";
import { ScanCard } from "@/components/ScanCard";
import { api, type Scan } from "@/lib/api";
import { Search, Filter } from "lucide-react";

export default function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [filteredScans, setFilteredScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    filterScans();
  }, [scans, searchTerm, statusFilter]);

  const loadScans = async () => {
    try {
      const data = await api.getScans();
      setScans(data.results || []);
    } catch (err) {
      console.error("Failed to load scans:", err);
    } finally {
      setIsLoading(false);
    }
  };

  const filterScans = () => {
    let filtered = scans;

    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(
        (s) =>
          s.domain.toLowerCase().includes(term) ||
          s.url.toLowerCase().includes(term)
      );
    }

    if (statusFilter !== "all") {
      filtered = filtered.filter((s) => s.status === statusFilter);
    }

    setFilteredScans(filtered);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold">Scan History</h1>
        <p className="text-muted-foreground mt-1">
          View all your previous security scans
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by domain or URL..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full h-10 pl-10 pr-4 rounded-lg bg-card border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all outline-none text-sm"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="h-10 px-3 rounded-lg bg-card border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all outline-none text-sm"
          >
            <option value="all">All Status</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="failed">Failed</option>
            <option value="pending">Pending</option>
          </select>
        </div>
      </div>

      {/* Scans List */}
      {filteredScans.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredScans.map((scan) => (
            <ScanCard key={scan.id} scan={scan} />
          ))}
        </div>
      ) : (
        <div className="text-center py-12 text-muted-foreground">
          {scans.length === 0
            ? "No scans yet. Start by scanning a URL!"
            : "No scans match your filters."}
        </div>
      )}
    </div>
  );
}
