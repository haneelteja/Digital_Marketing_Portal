'use client';

import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import { supabase } from '../../lib/supabaseClient';
import logger from '../../lib/logger';
import { Client } from '../types/user';

// Global client cache context
const ClientCacheContext = createContext<{
  clients: Client[];
  loading: boolean;
  refreshClients: () => Promise<void>;
}>({
  clients: [],
  loading: false,
  refreshClients: async () => {}
});

// Client cache provider
export const ClientCacheProvider = ({ children }: { children: React.ReactNode }) => {
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true); // Start with true for initial load
  const [cache, setCache] = useState<{data: Client[], timestamp: number} | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const CACHE_DURATION = 30000; // 30 seconds

  const refreshClients = useCallback(async () => {
    // Get current cache state using functional update to avoid stale closure
    const currentCache = cache;
    const isFresh = currentCache && Date.now() - currentCache.timestamp < CACHE_DURATION;
    
    if (isFresh) {
      setClients(currentCache.data);
      setLoading(false);
      // Revalidate in background without showing loading state
    }

    // Abort any in-flight request
    if (abortRef.current) {
      abortRef.current.abort();
    }
    const controller = new AbortController();
    abortRef.current = controller;

    if (!isFresh) setLoading(true);
    try {
      // Get auth token from localStorage (avoids hanging on getSession)
      const getAuthToken = (): string | null => {
        if (typeof window === 'undefined') return null;
        
        try {
          const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
          if (supabaseUrl) {
            const projectRef = supabaseUrl.match(/https?:\/\/([^.]+)\.supabase\.co/)?.[1];
            if (projectRef) {
              const possibleKeys = [
                `sb-${projectRef}-auth-token`,
                `supabase.auth.token`,
              ];
              
              // Check all keys starting with "sb-"
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
                      return token;
                    }
                  } catch (parseError) {
                    if (storedSession.startsWith('eyJ')) {
                      return storedSession;
                    }
                  }
                }
              }
            }
          }
        } catch (error) {
          logger.error('Error reading auth token from localStorage:', error);
        }
        
        return null;
      };

      const token = getAuthToken();
      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const res = await fetch('/api/clients', { 
        signal: controller.signal, 
        cache: 'no-store',
        headers
      });
      if (!res.ok) {
        const errorText = await res.text().catch(() => 'Unknown error');
        throw new Error(`Failed to load clients: ${res.status} - ${errorText}`);
      }
      const json = await res.json();
      const clientsData: Client[] = (json.data || []) as Client[];
      setClients(clientsData);
      setCache({ data: clientsData, timestamp: Date.now() });
    } catch (error) {
      // Check if request was aborted - don't update state if so
      if (controller.signal.aborted || (error as any)?.name === 'AbortError') {
        logger.log('Client fetch aborted');
        return;
      } else {
        logger.error('Error loading clients:', error);
        setClients([]);
        if (!isFresh) setLoading(false);
      }
    } finally {
      if (!controller.signal.aborted && !isFresh) {
        setLoading(false);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Empty deps - use functional updates instead

  useEffect(() => {
    // Initial load
    refreshClients();

    // Revalidate on visibility change (tab focus)
    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        refreshClients();
      }
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
      if (abortRef.current) abortRef.current.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Only run once on mount

  return (
    <ClientCacheContext.Provider value={{ clients, loading, refreshClients }}>
      {children}
    </ClientCacheContext.Provider>
  );
};

// Hook to use client cache
export const useClientCache = () => useContext(ClientCacheContext);
