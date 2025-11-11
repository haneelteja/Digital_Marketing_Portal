# Performance Implementation Guide
## Quick Start Guide for Performance Improvements

This guide provides step-by-step instructions for implementing the performance improvements outlined in the main analysis document.

---

## Phase 1: Critical Fixes (Week 1-2)

### Step 1: Install Required Dependencies

```bash
# Redis client
npm install ioredis
npm install --save-dev @types/ioredis

# React Query (for data fetching)
npm install @tanstack/react-query

# Performance monitoring (optional)
npm install @sentry/nextjs  # or your preferred monitoring tool
```

### Step 2: Set Up Redis

#### Option A: Local Development (Docker)

```bash
# Create docker-compose.redis.yml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes

volumes:
  redis-data:

# Run Redis
docker-compose -f docker-compose.redis.yml up -d
```

#### Option B: Cloud Redis (Production)

- **Supabase:** Use Supabase's built-in Redis (if available)
- **Upstash:** Free tier available (https://upstash.com)
- **Redis Cloud:** Free tier available (https://redis.com/cloud)

#### Environment Variables

Add to `.env.local`:
```env
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# For production
# REDIS_HOST=your-redis-host.com
# REDIS_PORT=6380
# REDIS_PASSWORD=your-password
```

### Step 3: Implement Cache Service

The cache service is already created in `src/lib/cache.ts`. 

**Test the connection:**
```typescript
// src/app/api/health/route.ts
import { CacheService } from '../../../lib/cache';

export async function GET() {
  const redisHealthy = await CacheService.healthCheck();
  return Response.json({ 
    redis: redisHealthy ? 'connected' : 'disconnected' 
  });
}
```

### Step 4: Add Database Indexes

Run this SQL in your Supabase SQL Editor:

```sql
-- See PERFORMANCE_ANALYSIS_AND_IMPROVEMENT_PLAN.md Section 2.2
-- Copy the index creation SQL from that section
```

### Step 5: Fix In-Memory Filtering

**Priority:** `src/app/api/artworks/route.ts`

1. Review the current implementation (lines 124-143)
2. Replace with database-level filtering (see optimized example in main document)
3. Test with various filters

---

## Phase 2: High Priority (Week 3-4)

### Step 6: Set Up React Query

```typescript
// src/app/providers.tsx
'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30000, // 30 seconds
        gcTime: 300000, // 5 minutes
        refetchOnWindowFocus: false,
        retry: 2,
      },
    },
  }));

  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
}

// src/app/layout.tsx
import { Providers } from './providers';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}
```

### Step 7: Create Custom Hooks

```typescript
// src/hooks/useCalendarEntries.ts
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../utils/apiClient';

export const useCalendarEntries = (filters: {
  startDate?: string;
  endDate?: string;
  clientId?: string;
  status?: string;
}) => {
  return useQuery({
    queryKey: ['calendar-entries', filters],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filters.startDate) params.set('startDate', filters.startDate);
      if (filters.endDate) params.set('endDate', filters.endDate);
      if (filters.clientId) params.set('clientId', filters.clientId);
      if (filters.status) params.set('status', filters.status);
      
      return apiClient.get(`/api/calendar-entries?${params}`);
    },
    staleTime: 30000,
    gcTime: 300000,
  });
};
```

### Step 8: Refactor Dashboard Component

**Approach:**
1. Create `src/components/Dashboard/` directory
2. Split into smaller components:
   - `DashboardContainer.tsx` - Main container
   - `DashboardSidebar.tsx` - Sidebar navigation
   - `CalendarView.tsx` - Calendar component
   - `AddPostView.tsx` - Add post form
   - etc.

3. Create `src/contexts/DashboardContext.tsx` for shared state
4. Move logic to custom hooks

**See main document Section 1.1 for detailed example.**

---

## Testing & Validation

### Performance Testing

```bash
# Install testing tools
npm install --save-dev @playwright/test
npm install --save-dev k6

# Run Lighthouse
npm install -g lighthouse
lighthouse http://localhost:3000 --view
```

### Monitoring Setup

1. **Vercel Analytics** (if using Vercel)
   - Automatically enabled
   - View in Vercel dashboard

2. **Sentry** (Error + Performance)
   ```bash
   npm install @sentry/nextjs
   npx @sentry/wizard@latest -i nextjs
   ```

3. **Custom Monitoring**
   - Use `PerformanceMonitor` from `src/lib/performance.ts`
   - Create API endpoint to collect metrics

---

## Rollout Strategy

### Development Environment
1. Implement changes in feature branch
2. Test locally with Redis
3. Run performance tests
4. Compare metrics before/after

### Staging Environment
1. Deploy to staging
2. Monitor for 24-48 hours
3. Validate cache hit rates
4. Check error rates

### Production Environment
1. Deploy during low-traffic period
2. Monitor closely for first hour
3. Have rollback plan ready
4. Gradually increase cache TTLs

---

## Troubleshooting

### Redis Connection Issues
```typescript
// Check Redis connection
import redis from './lib/cache';
redis.ping().then(() => console.log('Connected')).catch(console.error);
```

### Cache Not Working
- Check Redis is running
- Verify environment variables
- Check cache keys are being generated correctly
- Monitor cache hit/miss rates

### Performance Not Improving
- Verify indexes are created
- Check query execution plans
- Monitor database query times
- Review React component re-renders

---

## Success Metrics

Track these metrics before and after implementation:

1. **API Response Times** (p50, p95, p99)
2. **Database Query Times**
3. **Cache Hit Rates**
4. **Page Load Times** (FCP, LCP, TTI)
5. **Bundle Sizes**
6. **Memory Usage**
7. **Error Rates**

---

## Next Steps

1. Review the main `PERFORMANCE_ANALYSIS_AND_IMPROVEMENT_PLAN.md`
2. Prioritize improvements based on your needs
3. Set up monitoring to establish baseline
4. Begin Phase 1 implementation
5. Measure and iterate

For detailed code examples, see the main performance analysis document.

