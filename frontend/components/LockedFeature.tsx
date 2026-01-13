"use client";

import { ReactNode } from "react";
import { useFeature } from "@/lib/useFeatureGate";
import { Lock, Sparkles } from "lucide-react";
import Link from "next/link";

interface LockedFeatureProps {
  feature: string;
  children: ReactNode;
  fallback?: ReactNode;
  showUpgradePrompt?: boolean;
}

/**
 * Wrapper component for paid features.
 * Shows children if feature is available, otherwise shows locked state.
 */
// Simplified LockedFeature - Does not lock anything since all features are free
export function LockedFeature({
  feature,
  children,
  fallback,
  showUpgradePrompt = true,
}: LockedFeatureProps) {
  // Always render children as if feature is available
  return <>{children}</>;
}

export function PaidBadge({ feature }: { feature?: string } = {}) {
  // Never show "Pro" badge
  return null;
}

export function LockedButton({
  feature,
  children,
  className = "",
  ...props
}: {
  feature: string;
  children: ReactNode;
  className?: string;
  [key: string]: any;
}) {
  // Always just a normal button
  return (
    <button className={className} {...props}>
      {children}
    </button>
  );
}
