/**
 * Enhanced API Client with timeout, retry, and error handling
 */

import { ErrorHandler, withTimeout, retryWithBackoff } from './errorHandler';

const DEFAULT_TIMEOUT = 20000; // 20 seconds
const DEFAULT_RETRIES = 2;

interface RequestOptions extends RequestInit {
  timeout?: number;
  retries?: number;
  skipAuth?: boolean;
}

// Import supabase client directly (only used on client side)
// This ensures we use the same instance that has the session
let supabaseInstance: any = null;
let getSessionPromise: Promise<any> | null = null; // Lock to prevent concurrent getSession calls

function getSupabase() {
  if (typeof window === 'undefined') {
    return null; // SSR
  }
  
  if (!supabaseInstance) {
    // Use dynamic import but cache the result
    import('../../lib/supabaseClient').then((module) => {
      supabaseInstance = module.supabase;
    }).catch(() => {
      // Ignore import errors
    });
    
    // If not loaded yet, try synchronous access (might work if already imported elsewhere)
    try {
      // This will only work if supabaseClient was already imported by another module
      const module = require('../../lib/supabaseClient');
      if (module?.supabase) {
        supabaseInstance = module.supabase;
      }
    } catch {
      // Ignore require errors
    }
  }
  
  return supabaseInstance;
}

class ApiClient {
  private async getAuthToken(): Promise<string | null> {
    try {
      console.log('[apiClient.getAuthToken] Starting to get auth token...');
      
      // First, try to read directly from localStorage (fastest, no async call)
      if (typeof window !== 'undefined') {
        try {
          const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
          if (supabaseUrl) {
            // Extract project ref from URL (e.g., https://xyz.supabase.co -> xyz)
            const projectRef = supabaseUrl.match(/https?:\/\/([^.]+)\.supabase\.co/)?.[1];
            if (projectRef) {
              // Try multiple possible key formats
              const possibleKeys = [
                `sb-${projectRef}-auth-token`,
                `supabase.auth.token`,
                `sb-${projectRef}-auth-token-code-verifier`,
              ];
              
              // Also check all keys starting with "sb-"
              for (let i = 0; i < window.localStorage.length; i++) {
                const key = window.localStorage.key(i);
                if (key && key.startsWith('sb-') && key.includes(projectRef)) {
                  possibleKeys.push(key);
                }
              }
              
              for (const storageKey of possibleKeys) {
                const storedSession = window.localStorage.getItem(storageKey);
                if (storedSession) {
                  try {
                    const sessionData = JSON.parse(storedSession);
                    // Try different possible token locations
                    const token = sessionData?.access_token 
                      || sessionData?.session?.access_token
                      || sessionData?.currentSession?.access_token;
                    
                    if (token && typeof token === 'string') {
                      console.log('[apiClient.getAuthToken] Token retrieved from localStorage:', storageKey);
                      return token;
                    }
                  } catch (parseError) {
                    // Try to parse as plain string (some formats store token directly)
                    if (storedSession.startsWith('eyJ')) {
                      // Looks like a JWT token
                      console.log('[apiClient.getAuthToken] Token retrieved from localStorage (JWT format):', storageKey);
                      return storedSession;
                    }
                  }
                }
              }
            }
          }
        } catch (localStorageError) {
          console.warn('[apiClient.getAuthToken] localStorage read failed:', localStorageError);
        }
      }
      
      // If localStorage didn't work, try getSession() with a very short timeout
      console.log('[apiClient.getAuthToken] localStorage not available, trying getSession()...');
      
      // Get supabase instance
      let supabase = getSupabase();
      
      // If not available, try async import
      if (!supabase) {
        console.log('[apiClient.getAuthToken] Supabase not cached, importing...');
        const module = await import('../../lib/supabaseClient');
        supabase = module.supabase;
        supabaseInstance = supabase;
      }
      
      if (!supabase) {
        console.error('[apiClient.getAuthToken] Supabase not available (SSR?)');
        return null;
      }
      
      console.log('[apiClient.getAuthToken] Supabase client loaded, getting session...');
      
      // Use a lock to prevent concurrent getSession calls (they can block each other)
      if (!getSessionPromise) {
        getSessionPromise = supabase.auth.getSession().finally(() => {
          // Clear the lock after 100ms to allow new calls
          setTimeout(() => {
            getSessionPromise = null;
          }, 100);
        });
      }
      
      const sessionPromise = getSessionPromise;
      
      // Use a very short timeout - getSession should be instant if session exists
      const SESSION_TIMEOUT = 1000; // 1 second (reduced from 2s)
      let timeoutId: NodeJS.Timeout | undefined;
      
      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutId = setTimeout(() => {
          console.warn('[apiClient.getAuthToken] Session fetch timeout after 1s, falling back to localStorage');
          reject(new Error('Session fetch timeout'));
        }, SESSION_TIMEOUT);
      });
      
      try {
        const sessionResult = await Promise.race([sessionPromise, timeoutPromise]);
        if (timeoutId) clearTimeout(timeoutId);
        const token = sessionResult.data?.session?.access_token || null;
        console.log('[apiClient.getAuthToken] Session retrieved from getSession():', token ? 'present' : 'null');
        return token;
      } catch (raceError) {
        if (timeoutId) clearTimeout(timeoutId);
        
        // If timeout, try localStorage again as final fallback
        console.log('[apiClient.getAuthToken] getSession() timed out, trying localStorage fallback...');
        if (typeof window !== 'undefined') {
          try {
            const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
            if (supabaseUrl) {
              const projectRef = supabaseUrl.match(/https?:\/\/([^.]+)\.supabase\.co/)?.[1];
              if (projectRef) {
                // Try multiple possible key formats
                const possibleKeys = [
                  `sb-${projectRef}-auth-token`,
                  `supabase.auth.token`,
                ];
                
                // Also check all keys starting with "sb-"
                for (let i = 0; i < window.localStorage.length; i++) {
                  const key = window.localStorage.key(i);
                  if (key && key.startsWith('sb-') && key.includes(projectRef)) {
                    possibleKeys.push(key);
                  }
                }
                
                for (const storageKey of possibleKeys) {
                  const storedSession = window.localStorage.getItem(storageKey);
                  if (storedSession) {
                    try {
                      const sessionData = JSON.parse(storedSession);
                      const token = sessionData?.access_token 
                        || sessionData?.session?.access_token
                        || sessionData?.currentSession?.access_token;
                      
                      if (token && typeof token === 'string') {
                        console.log('[apiClient.getAuthToken] Token retrieved from localStorage fallback:', storageKey);
                        return token;
                      }
                    } catch (parseError) {
                      // Try to parse as plain string (some formats store token directly)
                      if (storedSession.startsWith('eyJ')) {
                        console.log('[apiClient.getAuthToken] Token retrieved from localStorage fallback (JWT format):', storageKey);
                        return storedSession;
                      }
                    }
                  }
                }
              }
            }
          } catch (localStorageError) {
            console.warn('[apiClient.getAuthToken] localStorage fallback failed:', localStorageError);
          }
        }
        
        console.error('[apiClient.getAuthToken] All attempts failed, returning null');
        return null;
      }
    } catch (error) {
      console.error('[apiClient.getAuthToken] Error in getAuthToken:', error);
      ErrorHandler.logError(error, { context: 'getAuthToken' });
      return null;
    }
  }

  private async makeRequest(
    url: string,
    options: RequestOptions = {}
  ): Promise<Response> {
    console.log(`[apiClient.makeRequest] Starting makeRequest for: ${url}`);
    const {
      timeout = DEFAULT_TIMEOUT,
      skipAuth = false,
      headers = {},
      ...fetchOptions
    } = options;

    // Get auth token if not skipped
    let authToken: string | null = null;
    if (!skipAuth) {
      console.log(`[apiClient.makeRequest] Getting auth token...`);
      authToken = await this.getAuthToken();
      console.log(`[apiClient.makeRequest] Auth token retrieved:`, authToken ? 'present' : 'null');
      if (!authToken) {
        throw new Error('Authentication required. Please refresh the page and log in again.');
      }
    } else {
      console.log(`[apiClient.makeRequest] Skipping auth (skipAuth=true)`);
    }

    // Prepare headers
    const requestHeaders: Record<string, string> = {
      ...(headers as Record<string, string>),
    };
    
    // Only set Content-Type for requests with body (POST, PUT, PATCH)
    if (fetchOptions.body && !requestHeaders['Content-Type']) {
      requestHeaders['Content-Type'] = 'application/json';
    }

    if (authToken) {
      requestHeaders['Authorization'] = `Bearer ${authToken}`;
    }

    console.log(`[apiClient] Making request to: ${url}`);
    
    // Create fetch promise with signal support
    const fetchPromise = fetch(url, {
      ...fetchOptions,
      headers: requestHeaders,
      signal: options.signal, // Pass through AbortController signal
    });

    console.log(`[apiClient] Fetch promise created, waiting for response (timeout: ${timeout}ms)...`);
    
    // Add timeout (but respect AbortController signal first)
    const response = await withTimeout(fetchPromise, timeout);
    
    console.log(`[apiClient] Response received: ${response.status} ${response.statusText}`);

    // Handle non-OK responses
    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
      
      try {
        const errorData = JSON.parse(errorText);
        errorMessage = errorData.error || errorData.message || errorMessage;
      } catch {
        if (errorText) {
          errorMessage = errorText;
        }
      }

      const error = new Error(errorMessage) as Error & { statusCode?: number };
      error.statusCode = response.status;
      throw error;
    }

    return response;
  }

  async request<T>(
    url: string,
    options: RequestOptions = {}
  ): Promise<T> {
    const { retries = DEFAULT_RETRIES } = options;
    
    console.log(`[apiClient.request] Starting request to: ${url}`, { method: options.method, retries });

    try {
      console.log(`[apiClient.request] Calling retryWithBackoff...`);
      const response = await retryWithBackoff(
        () => {
          console.log(`[apiClient.request] retryWithBackoff callback executing, calling makeRequest...`);
          return this.makeRequest(url, options);
        },
        retries
      );
      console.log(`[apiClient.request] Response received from retryWithBackoff`);

      const data = await response.json();
      
      // Check if response contains an error
      if (data && typeof data === 'object' && 'error' in data) {
        const errorMessage = (data.error as { message?: string }).message || 'An error occurred';
        const error = new Error(errorMessage) as Error & { statusCode?: number };
        error.statusCode = response.status;
        throw error;
      }
      
      return data.data || data;
    } catch (error) {
      // Skip logging for aborted requests
      if (error instanceof Error && (error.name === 'AbortError' || error.message.includes('aborted'))) {
        throw error; // Re-throw without logging
      }
      
      // If error is already an Error with statusCode, re-throw it
      if (error instanceof Error && 'statusCode' in error) {
        ErrorHandler.logError(error, { url, method: options.method || 'GET' });
        throw error;
      }
      
      ErrorHandler.logError(error, { url, method: options.method || 'GET' });
      throw new Error(ErrorHandler.getUserMessage(error));
    }
  }

  async get<T>(url: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(url, { ...options, method: 'GET' });
  }

  async post<T>(url: string, body?: unknown, options?: RequestOptions): Promise<T> {
    console.log(`[apiClient.post] POST request to: ${url}`, { body });
    try {
      const result = await this.request<T>(url, {
        ...options,
        method: 'POST',
        body: JSON.stringify(body),
      });
      console.log(`[apiClient.post] Request completed successfully`);
      return result;
    } catch (error) {
      console.error(`[apiClient.post] Request failed:`, error);
      throw error;
    }
  }

  async put<T>(url: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>(url, {
      ...options,
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  async delete<T>(url: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(url, { ...options, method: 'DELETE' });
  }
}

export const apiClient = new ApiClient();


