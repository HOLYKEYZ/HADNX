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
export function LockedFeature({
  feature,
  children,
  fallback,
  showUpgradePrompt = true,
}: LockedFeatureProps) {
  const { available, loading, isPaid, featureInfo } = useFeature(feature);

  if (loading) {
    return (
      <div className="animate-pulse bg-muted/50 rounded-lg h-20" />
    );
  }

  if (available) {
    return <>{children}</>;
  }

  if (fallback) {
    return <>{fallback}</>;
  }

  if (!showUpgradePrompt) {
    return null;
  }

  return (
    <div className="relative">
      {/* Blurred preview of children */}
      <div className="blur-sm opacity-50 pointer-events-none select-none">
        {children}
      </div>

      {/* Overlay with upgrade prompt */}
      <div className="absolute inset-0 flex items-center justify-center bg-background/80 backdrop-blur-sm rounded-lg">
        <div className="text-center p-6 max-w-sm">
          <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
            <Lock className="w-6 h-6 text-primary" />
          </div>
          <h3 className="text-lg font-semibold mb-2">
            {featureInfo?.name || "Premium Feature"}
          </h3>
          <p className="text-sm text-muted-foreground mb-4">
            {featureInfo?.description || "This feature requires a paid subscription."}
          </p>
          <Link
            href="/pricing"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors"
          >
            <Sparkles className="w-4 h-4" />
            Upgrade to Pro
          </Link>
        </div>
      </div>
    </div>
  );
}

/**
 * Badge to indicate a paid feature.
 * If `feature` is provided, only shows when the feature is NOT available (i.e., locked).
 */
export function PaidBadge({ feature }: { feature?: string } = {}) {
  const { available } = useFeature(feature || "");
  
  // If a feature is specified and user has access, don't show the badge
  if (feature && available) {
    return null;
  }
  
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-medium">
      <Sparkles className="w-3 h-3" />
      Pro
    </span>
  );
}

/**
 * Button that shows locked state for paid features.
 */
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
  const { available, loading, featureInfo } = useFeature(feature);

  if (loading) {
    return (
      <button
        className={`opacity-50 cursor-not-allowed ${className}`}
        disabled
        {...props}
      >
        {children}
      </button>
    );
  }

  if (!available) {
    return (
      <Link
        href="/pricing"
        className={`inline-flex items-center gap-2 ${className}`}
        title={`Requires ${featureInfo?.name || "Pro subscription"}`}
      >
        <Lock className="w-4 h-4" />
        {children}
        <PaidBadge />
      </Link>
    );
  }

  return (
    <button className={className} {...props}>
      {children}
    </button>
  );
}
