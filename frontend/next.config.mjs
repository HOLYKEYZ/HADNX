/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Enable standalone output for Docker deployments
  output: 'standalone',
  async rewrites() {
    // Only proxy in production (Vercel). Locally, use NEXT_PUBLIC_API_URL directly.
    if (process.env.NODE_ENV === 'production') {
      return [
        {
          source: '/api/:path*',
          destination: 'https://hadnx.onrender.com/api/:path*',
        },
      ];
    }
    // Local development: proxy to local backend
    return [
      {
        source: '/api/:path*',
        destination: 'http://127.0.0.1:9001/api/:path*',
      },
    ];
  },
};

export default nextConfig;
