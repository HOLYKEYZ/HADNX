import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: "Hadnx - Web Security Posture Analysis",
  description: "Modern website security posture analysis with actionable fixes. Scan your website for security headers, cookies, TLS configuration, and more.",
  keywords: ["security", "web security", "headers", "TLS", "SSL", "security scanner"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} font-sans min-h-screen bg-background`}>
        {children}
      </body>
    </html>
  );
}
