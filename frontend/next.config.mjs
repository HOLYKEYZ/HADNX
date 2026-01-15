/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Align with Django's APPEND_SLASH behavior
  trailingSlash: true,
  // Enable standalone output for Docker deployments
  output: 'standalone',
  async rewrites() {
    // Only proxy in production (Vercel). Locally, use NEXT_PUBLIC_API_URL directly.
    if (process.env.NODE_ENV === 'production') {
      return [
        {
          source: '/api/:path*/', 
          destination: 'https://hadnx.onrender.com/api/:path*/',
        },
        {
          source: '/api/:path*',
          destination: 'https://hadnx.onrender.com/api/:path*/',
        },
      ];
    }
    // Local development: DO NOT PROXY.
    // Frontend should talk directly to http://127.0.0.1:9001/api via NEXT_PUBLIC_API_URL
    return [];
  },
};

export default nextConfig;
