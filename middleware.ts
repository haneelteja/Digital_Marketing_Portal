import { NextRequest, NextResponse } from 'next/server';

// Simple in-memory rate limiter per IP and route. Suitable for dev and small deployments.
// For production at scale, replace with an external store (e.g., Redis) or edge KV.
type Bucket = { tokens: number; updatedAt: number };
const buckets: Map<string, Bucket> = new Map();

const WINDOW_MS = 60_000; // 1 minute
const MAX_TOKENS = 60; // 60 requests per minute per IP per route

function getKey(ip: string, path: string): string {
  return `${ip}:${path}`;
}

function takeToken(now: number, key: string): boolean {
  const bucket = buckets.get(key) || { tokens: MAX_TOKENS, updatedAt: now };
  // Refill tokens based on elapsed time
  const elapsed = now - bucket.updatedAt;
  if (elapsed > 0) {
    const refill = Math.floor((elapsed / WINDOW_MS) * MAX_TOKENS);
    if (refill > 0) {
      bucket.tokens = Math.min(MAX_TOKENS, bucket.tokens + refill);
      bucket.updatedAt = now;
    }
  }
  if (bucket.tokens > 0) {
    bucket.tokens -= 1;
    buckets.set(key, bucket);
    return true;
  }
  buckets.set(key, bucket);
  return false;
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (!pathname.startsWith('/api')) {
    return NextResponse.next();
  }

  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || '127.0.0.1';
  const now = Date.now();
  const key = getKey(ip, pathname);

  if (!takeToken(now, key)) {
    return NextResponse.json(
      { error: 'Too many requests. Please try again later.' },
      { status: 429, headers: { 'Retry-After': '60' } }
    );
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/api/:path*'],
};


