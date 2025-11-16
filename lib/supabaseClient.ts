// lib/supabaseClient.ts
import { createClient } from '@supabase/supabase-js';
import logger from './logger';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

// Validate environment variables at runtime (not during build)
// During build time, we use placeholder values to allow the build to complete
// Validation happens at runtime when the app actually runs

// Runtime validation - check if we're using placeholder values
if (typeof window !== 'undefined') {
  // Client-side: validate that real values are set
  if (!supabaseUrl || supabaseUrl === 'https://placeholder.supabase.co' || 
      !supabaseAnonKey || supabaseAnonKey === 'placeholder-key') {
    console.error('⚠️ Supabase environment variables are not configured!');
    console.error('Please set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY in your Vercel environment variables.');
  }
}

// Only log in development, and only once (not on every import)
if (process.env.NODE_ENV === 'development' && typeof window !== 'undefined') {
  // Check if we've already logged to avoid duplicate logs
  if (!(window as any).__supabase_logged) {
    logger.log('Supabase initialized');
    (window as any).__supabase_logged = true;
  }
}

// Use placeholder values during build time to avoid errors
// At runtime, if env vars are missing, this will cause auth to fail gracefully
export const supabase = createClient(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseAnonKey || 'placeholder-key',
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      storage: typeof window !== 'undefined' ? window.localStorage : undefined
    },
    global: {
      headers: {
        'X-Client-Info': 'supabase-js-web'
      }
    }
  }
);
