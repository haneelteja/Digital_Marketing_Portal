/**
 * Comprehensive Error Handling Utilities
 * Provides consistent error handling across the application
 */

export interface AppError {
  message: string;
  code?: string;
  statusCode?: number;
  details?: Record<string, unknown>;
  timestamp: string;
}

export class ErrorHandler {
  /**
   * Normalize errors to a consistent format
   */
  static normalizeError(error: unknown): AppError {
    const timestamp = new Date().toISOString();

    if (error instanceof Error) {
      const errorWithExtras = error as Error & { code?: string; statusCode?: number; status?: number };
      
      // Handle AbortError specifically
      if (error.name === 'AbortError' || error.message.includes('aborted')) {
        return {
          message: 'Request was cancelled',
          code: 'ABORTED',
          statusCode: 0,
          details: {
            name: error.name,
            message: error.message,
          },
          timestamp,
        };
      }
      
      return {
        message: error.message || 'An unexpected error occurred',
        code: errorWithExtras.code || error.name,
        statusCode: errorWithExtras.statusCode || errorWithExtras.status,
        details: {
          name: error.name,
          stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
        },
        timestamp,
      };
    }

    if (typeof error === 'string') {
      return {
        message: error,
        timestamp,
      };
    }

    if (error && typeof error === 'object') {
      const errorObj = error as Record<string, unknown> & { message?: string; code?: string; statusCode?: number; status?: number };
      return {
        message: errorObj.message || 'An unexpected error occurred',
        code: errorObj.code,
        statusCode: errorObj.statusCode || errorObj.status,
        details: errorObj,
        timestamp,
      };
    }

    return {
      message: 'An unexpected error occurred',
      timestamp,
    };
  }

  /**
   * Get user-friendly error message
   */
  static getUserMessage(error: unknown): string {
    const normalized = this.normalizeError(error);

    // Network errors
    if (normalized.message.includes('fetch') || normalized.message.includes('network')) {
      return 'Network error. Please check your internet connection and try again.';
    }

    // Authentication errors
    if (normalized.statusCode === 401 || normalized.message.includes('auth') || normalized.message.includes('unauthorized')) {
      return 'Your session has expired. Please refresh the page and log in again.';
    }

    // Permission errors
    if (normalized.statusCode === 403 || normalized.message.includes('permission') || normalized.message.includes('forbidden')) {
      return 'You do not have permission to perform this action.';
    }

    // Not found errors
    if (normalized.statusCode === 404 || normalized.message.includes('not found')) {
      return 'The requested resource was not found.';
    }

    // Server errors
    if (normalized.statusCode && normalized.statusCode >= 500) {
      return 'Server error. Please try again later or contact support if the problem persists.';
    }

    // Rate limiting
    if (normalized.statusCode === 429 || normalized.message.includes('rate limit')) {
      return 'Too many requests. Please wait a moment and try again.';
    }

    // Validation errors
    if (normalized.statusCode === 400 || normalized.message.includes('validation') || normalized.message.includes('invalid')) {
      return normalized.message || 'Invalid input. Please check your data and try again.';
    }

    // Return the error message if it's user-friendly, otherwise generic message
    return normalized.message || 'An error occurred. Please try again.';
  }

  /**
   * Log error with context
   */
  static logError(error: unknown, context?: Record<string, unknown>): void {
    const normalized = this.normalizeError(error);
    
    // Skip logging for aborted requests (they're intentional)
    if (normalized.code === 'ABORTED') {
      return;
    }
    
    const logData = {
      ...normalized,
      context,
      environment: process.env.NODE_ENV,
    };

    // In development, log to console with more details
    if (process.env.NODE_ENV === 'development') {
      console.error('Error logged:', {
        message: logData.message,
        code: logData.code,
        statusCode: logData.statusCode,
        context: logData.context,
        details: logData.details,
        timestamp: logData.timestamp,
      });
      
      // Also log the original error for debugging
      if (error instanceof Error) {
        console.error('Original error:', error);
      }
    }

    // In production, you could send to error tracking service (Sentry, LogRocket, etc.)
    // Example: Sentry.captureException(error, { extra: context });
  }

  /**
   * Handle API errors with retry logic
   */
  static async handleApiError(
    error: unknown,
    retryFn?: () => Promise<Response>,
    maxRetries: number = 2
  ): Promise<never> {
    const normalized = this.normalizeError(error);
    
    // Retry on network errors or 5xx errors
    const shouldRetry = 
      normalized.message.includes('network') ||
      normalized.message.includes('fetch') ||
      (normalized.statusCode && normalized.statusCode >= 500) ||
      normalized.statusCode === 429;

    if (shouldRetry && retryFn && maxRetries > 0) {
      // Exponential backoff
      const delay = Math.pow(2, 2 - maxRetries) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
      
      try {
        const response = await retryFn();
        if (response.ok) {
          return response.json() as never;
        }
      } catch {
        // Continue to throw original error if retry fails
      }
    }

    this.logError(error);
    throw new Error(this.getUserMessage(error));
  }
}

/**
 * Safe async wrapper with error handling
 */
export async function safeAsync<T>(
  fn: () => Promise<T>,
  fallback?: T,
  onError?: (error: unknown) => void
): Promise<T | undefined> {
  try {
    return await fn();
  } catch (error) {
    ErrorHandler.logError(error);
    if (onError) {
      onError(error);
    }
    return fallback;
  }
}

/**
 * Create a timeout promise
 */
export function createTimeout(ms: number): Promise<never> {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`Operation timed out after ${ms}ms`)), ms);
  });
}

/**
 * Race a promise against a timeout
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  timeoutMessage?: string
): Promise<T> {
  const timeout = createTimeout(ms);
  try {
    return await Promise.race([promise, timeout]) as T;
  } catch (error) {
    if (error instanceof Error && error.message.includes('timed out')) {
      throw new Error(timeoutMessage || `Operation timed out after ${ms}ms`);
    }
    throw error;
  }
}

/**
 * Retry a function with exponential backoff
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  initialDelay: number = 1000
): Promise<T> {
  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt < maxRetries) {
        const delay = initialDelay * Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError;
}

