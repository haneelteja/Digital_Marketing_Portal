/**
 * Performance Monitoring Service
 * Tracks and reports performance metrics
 */

interface PerformanceMetric {
  name: string;
  duration: number;
  timestamp: number;
  metadata?: Record<string, any>;
}

class PerformanceMonitor {
  private static metrics: PerformanceMetric[] = [];
  private static readonly MAX_METRICS = 1000;
  private static readonly SLOW_THRESHOLD = 1000; // 1 second

  /**
   * Create a performance mark
   */
  static mark(name: string): void {
    if (typeof performance !== 'undefined' && performance.mark) {
      try {
        performance.mark(name);
      } catch (error) {
        console.warn(`Performance mark failed for ${name}:`, error);
      }
    }
  }

  /**
   * Measure performance between two marks
   */
  static measure(name: string, startMark: string, endMark: string): number | null {
    if (typeof performance !== 'undefined' && performance.measure) {
      try {
        performance.measure(name, startMark, endMark);
        const measure = performance.getEntriesByName(name)[0] as PerformanceMeasure;
        return measure?.duration || null;
      } catch (error) {
        console.warn(`Performance measure failed for ${name}:`, error);
      }
    }
    return null;
  }

  /**
   * Track an async operation
   */
  static async trackApiCall<T>(
    name: string,
    fn: () => Promise<T>,
    metadata?: Record<string, any>
  ): Promise<T> {
    const startMark = `${name}-start`;
    const endMark = `${name}-end`;
    
    this.mark(startMark);
    const startTime = Date.now();
    
    try {
      const result = await fn();
      this.mark(endMark);
      
      const duration = this.measure(name, startMark, endMark) || (Date.now() - startTime);
      
      // Store metric
      this.recordMetric(name, duration, metadata);
      
      // Report slow queries
      if (duration > this.SLOW_THRESHOLD) {
        this.reportSlowQuery(name, duration, metadata);
      }
      
      return result;
    } catch (error) {
      this.mark(endMark);
      const duration = this.measure(`${name}-error`, startMark, endMark) || (Date.now() - startTime);
      
      this.recordMetric(`${name}-error`, duration, { ...metadata, error: true });
      throw error;
    }
  }

  /**
   * Record a performance metric
   */
  private static recordMetric(
    name: string,
    duration: number,
    metadata?: Record<string, any>
  ): void {
    const metric: PerformanceMetric = {
      name,
      duration,
      timestamp: Date.now(),
      metadata,
    };

    this.metrics.push(metric);

    // Keep only recent metrics
    if (this.metrics.length > this.MAX_METRICS) {
      this.metrics = this.metrics.slice(-this.MAX_METRICS);
    }

    // In production, send to monitoring service
    if (process.env.NODE_ENV === 'production') {
      this.sendToMonitoringService(metric);
    }
  }

  /**
   * Report slow queries
   */
  private static reportSlowQuery(
    name: string,
    duration: number,
    metadata?: Record<string, any>
  ): void {
    console.warn(`Slow operation detected: ${name} took ${duration.toFixed(2)}ms`, metadata);
    
    // Send to monitoring service (e.g., Datadog, New Relic, Sentry)
    if (process.env.NEXT_PUBLIC_MONITORING_ENABLED === 'true') {
      // Example: Send to external service
      // fetch('/api/monitoring/slow-query', {
      //   method: 'POST',
      //   body: JSON.stringify({ name, duration, metadata }),
      // }).catch(console.error);
    }
  }

  /**
   * Send metric to monitoring service
   */
  private static sendToMonitoringService(metric: PerformanceMetric): void {
    // Integrate with your monitoring service
    // Examples: Datadog, New Relic, Sentry, etc.
  }

  /**
   * Get performance statistics
   */
  static getStats(name?: string): {
    count: number;
    avgDuration: number;
    minDuration: number;
    maxDuration: number;
    p95: number;
    p99: number;
  } {
    const metrics = name 
      ? this.metrics.filter(m => m.name === name)
      : this.metrics;

    if (metrics.length === 0) {
      return {
        count: 0,
        avgDuration: 0,
        minDuration: 0,
        maxDuration: 0,
        p95: 0,
        p99: 0,
      };
    }

    const durations = metrics.map(m => m.duration).sort((a, b) => a - b);
    const sum = durations.reduce((a, b) => a + b, 0);
    const avg = sum / durations.length;
    const min = durations[0];
    const max = durations[durations.length - 1];
    const p95Index = Math.floor(durations.length * 0.95);
    const p99Index = Math.floor(durations.length * 0.99);

    return {
      count: metrics.length,
      avgDuration: avg,
      minDuration: min,
      maxDuration: max,
      p95: durations[p95Index] || 0,
      p99: durations[p99Index] || 0,
    };
  }

  /**
   * Clear all metrics
   */
  static clearMetrics(): void {
    this.metrics = [];
  }
}

export default PerformanceMonitor;

