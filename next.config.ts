import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  // Ensure Next.js treats this project as the workspace root when multiple lockfiles exist
  outputFileTracingRoot: path.resolve(__dirname),

  // Production optimizations
  compress: true,
  output: 'standalone',

  // Images optimization
  images: {
    formats: ['image/webp', 'image/avif'],
  },

  // Experimental performance features
  experimental: {
    optimizeCss: true,
    optimizePackageImports: ['exceljs', 'jspdf', 'react-day-picker'],
  },

  // Allow production builds to proceed even if type errors exist.
  // We already run separate type checks in CI/local.
  typescript: {
    ignoreBuildErrors: true,
  },

  // Minimal webpack tweaks for browser bundles
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
      };
    }
    return config;
  },

  // Security headers
  headers: async () => {
    const ContentSecurityPolicy = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https://*.supabase.co https://*.supabase.in",
      "font-src 'self' data:",
      "connect-src 'self' https://*.supabase.co https://*.supabase.in",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
    ].join('; ');

    const securityHeaders = [
      { key: 'Content-Security-Policy', value: ContentSecurityPolicy },
      { key: 'Referrer-Policy', value: 'no-referrer' },
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'X-XSS-Protection', value: '0' },
      { key: 'Strict-Transport-Security', value: 'max-age=15552000; includeSubDomains' },
      { key: 'Permissions-Policy', value: "camera=(), microphone=(), geolocation=()" },
    ];

    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
