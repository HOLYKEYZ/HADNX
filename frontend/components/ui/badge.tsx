import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-muted text-muted-foreground",
        destructive: "border-transparent bg-severity-critical text-white",
        outline: "text-foreground",
        critical: "border-severity-critical/30 bg-severity-critical/10 text-severity-critical",
        high: "border-severity-high/30 bg-severity-high/10 text-severity-high",
        medium: "border-severity-medium/30 bg-severity-medium/10 text-severity-medium",
        low: "border-severity-low/30 bg-severity-low/10 text-severity-low",
        info: "border-severity-info/30 bg-severity-info/10 text-severity-info",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
