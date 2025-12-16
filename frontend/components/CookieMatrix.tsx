import { CheckCircle, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";

interface Cookie {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string;
  is_session: boolean;
}

interface CookieMatrixProps {
  cookies: Cookie[];
}

export function CookieMatrix({ cookies }: CookieMatrixProps) {
  if (cookies.length === 0) {
    return (
      <p className="text-sm text-muted-foreground py-4 text-center">
        No cookies detected
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border">
            <th className="text-left py-3 px-4 font-medium">Cookie Name</th>
            <th className="text-center py-3 px-4 font-medium">Secure</th>
            <th className="text-center py-3 px-4 font-medium">HttpOnly</th>
            <th className="text-center py-3 px-4 font-medium">SameSite</th>
            <th className="text-center py-3 px-4 font-medium">Session</th>
          </tr>
        </thead>
        <tbody>
          {cookies.map((cookie, index) => (
            <tr
              key={index}
              className={cn(
                "border-b border-border/50",
                cookie.is_session && "bg-severity-high/5"
              )}
            >
              <td className="py-3 px-4 font-mono text-xs">
                {cookie.name}
                {cookie.is_session && (
                  <span className="ml-2 text-xs text-severity-high">(session)</span>
                )}
              </td>
              <td className="py-3 px-4 text-center">
                {cookie.secure ? (
                  <CheckCircle className="w-4 h-4 text-primary mx-auto" />
                ) : (
                  <XCircle className="w-4 h-4 text-severity-critical mx-auto" />
                )}
              </td>
              <td className="py-3 px-4 text-center">
                {cookie.httponly ? (
                  <CheckCircle className="w-4 h-4 text-primary mx-auto" />
                ) : (
                  <XCircle className="w-4 h-4 text-severity-critical mx-auto" />
                )}
              </td>
              <td className="py-3 px-4 text-center">
                <span
                  className={cn(
                    "text-xs font-medium px-2 py-1 rounded",
                    cookie.samesite === "Strict" && "bg-primary/10 text-primary",
                    cookie.samesite === "Lax" && "bg-severity-medium/10 text-severity-medium",
                    cookie.samesite === "None" && "bg-severity-high/10 text-severity-high",
                    cookie.samesite === "Not Set" && "bg-severity-critical/10 text-severity-critical"
                  )}
                >
                  {cookie.samesite}
                </span>
              </td>
              <td className="py-3 px-4 text-center">
                {cookie.is_session ? (
                  <span className="text-xs text-severity-high">Yes</span>
                ) : (
                  <span className="text-xs text-muted-foreground">No</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
