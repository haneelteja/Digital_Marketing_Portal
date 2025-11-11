/**
 * Redis Cache Service
 * Provides caching layer for frequently accessed data
 */

import Redis from 'ioredis';

// Initialize Redis client
const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD,
  db: parseInt(process.env.REDIS_DB || '0', 10),
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  enableOfflineQueue: false,
  lazyConnect: false,
  keepAlive: 30000,
});

redis.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

redis.on('connect', () => {
  console.log('Redis Client Connected');
});

export class CacheService {
  private static PREFIX = 'dmp:'; // Digital Marketing Portal
  
  /**
   * Get value from cache
   */
  static async get<T>(key: string): Promise<T | null> {
    try {
      const data = await redis.get(`${this.PREFIX}${key}`);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error(`Cache get error for key ${key}:`, error);
      return null;
    }
  }
  
  /**
   * Set value in cache with TTL
   */
  static async set(
    key: string, 
    value: any, 
    ttlSeconds: number = 3600
  ): Promise<void> {
    try {
      await redis.setex(
        `${this.PREFIX}${key}`,
        ttlSeconds,
        JSON.stringify(value)
      );
    } catch (error) {
      console.error(`Cache set error for key ${key}:`, error);
    }
  }
  
  /**
   * Delete a specific key
   */
  static async del(key: string): Promise<void> {
    try {
      await redis.del(`${this.PREFIX}${key}`);
    } catch (error) {
      console.error(`Cache del error for key ${key}:`, error);
    }
  }
  
  /**
   * Invalidate all keys matching pattern
   */
  static async invalidatePattern(pattern: string): Promise<void> {
    try {
      const keys = await redis.keys(`${this.PREFIX}${pattern}`);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    } catch (error) {
      console.error(`Cache invalidate error for pattern ${pattern}:`, error);
    }
  }
  
  /**
   * Cache key generators
   */
  static keys = {
    user: (userId: string) => `user:${userId}`,
    userClients: (userId: string) => `user:${userId}:clients`,
    calendarEntries: (params: string) => `calendar:entries:${params}`,
    artworks: (params: string) => `artworks:${params}`,
    campaigns: (params: string) => `campaigns:${params}`,
    clients: () => `clients:all`,
    monthlyAnalytics: (params: string) => `analytics:${params}`,
  };
  
  /**
   * Health check
   */
  static async healthCheck(): Promise<boolean> {
    try {
      await redis.ping();
      return true;
    } catch {
      return false;
    }
  }
}

export default redis;

