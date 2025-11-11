/**
 * Centralized Logging Utility
 * Provides consistent logging across the application with environment awareness
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  component?: string;
  action?: string;
  userId?: string;
  [key: string]: unknown;
}

class Logger {
  private isDevelopment = process.env.NODE_ENV === 'development';
  private isProduction = process.env.NODE_ENV === 'production';

  private formatMessage(level: LogLevel, message: string, context?: LogContext): string {
    const timestamp = new Date().toISOString();
    const contextStr = context ? ` ${JSON.stringify(context)}` : '';
    return `[${timestamp}] [${level.toUpperCase()}] ${message}${contextStr}`;
  }

  private shouldLog(level: LogLevel): boolean {
    if (this.isDevelopment) {
      return true; // Log everything in development
    }
    // In production, only log warnings and errors
    return level === 'warn' || level === 'error';
  }

  debug(message: string, context?: LogContext): void {
    if (this.shouldLog('debug')) {
      console.debug(this.formatMessage('debug', message, context));
    }
  }

  info(message: string, context?: LogContext): void {
    if (this.shouldLog('info')) {
      console.info(this.formatMessage('info', message, context));
    }
  }

  warn(message: string, context?: LogContext): void {
    if (this.shouldLog('warn')) {
      console.warn(this.formatMessage('warn', message, context));
    }
    // In production, you might want to send warnings to error tracking service
  }

  error(message: string, error?: unknown, context?: LogContext): void {
    if (this.shouldLog('error')) {
      const errorDetails = error instanceof Error 
        ? { message: error.message, stack: this.isDevelopment ? error.stack : undefined }
        : error;
      
      console.error(this.formatMessage('error', message, { ...context, error: errorDetails }));
    }
    
    // In production, send to error tracking service (Sentry, LogRocket, etc.)
    if (this.isProduction && error) {
      // Example: Sentry.captureException(error, { extra: context });
    }
  }

  // Performance logging
  performance(operation: string, duration: number, context?: LogContext): void {
    if (this.isDevelopment || duration > 1000) { // Log slow operations in production
      this.info(`Performance: ${operation} took ${duration}ms`, context);
    }
  }

  // API request logging
  apiRequest(method: string, url: string, status?: number, duration?: number, context?: LogContext): void {
    if (this.isDevelopment) {
      const logMessage = `API ${method} ${url}${status ? ` - ${status}` : ''}${duration ? ` (${duration}ms)` : ''}`;
      this.info(logMessage, context);
    } else if (status && status >= 400) {
      // Log errors in production
      this.error(`API ${method} ${url} failed`, undefined, { ...context, status });
    }
  }
}

export const logger = new Logger();

// Convenience exports
export const log = {
  debug: (message: string, context?: LogContext) => logger.debug(message, context),
  info: (message: string, context?: LogContext) => logger.info(message, context),
  warn: (message: string, context?: LogContext) => logger.warn(message, context),
  error: (message: string, error?: unknown, context?: LogContext) => logger.error(message, error, context),
  performance: (operation: string, duration: number, context?: LogContext) => logger.performance(operation, duration, context),
  api: (method: string, url: string, status?: number, duration?: number, context?: LogContext) => logger.apiRequest(method, url, status, duration, context),
};



