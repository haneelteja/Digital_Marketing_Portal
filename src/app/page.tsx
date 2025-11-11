'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function Home() {
  const router = useRouter();
  const [isRedirecting, setIsRedirecting] = useState(false);

  useEffect(() => {
    // Prefetch dashboard route for faster navigation
    router.prefetch('/dashboard');
    
    // Redirect immediately on client-side (no artificial delay)
    // Use requestIdleCallback for non-blocking redirect
    if (typeof window !== 'undefined') {
      if ('requestIdleCallback' in window) {
        requestIdleCallback(() => {
          setIsRedirecting(true);
          router.push('/dashboard');
        }, { timeout: 100 });
      } else {
        // Fallback for browsers without requestIdleCallback
        setTimeout(() => {
          setIsRedirecting(true);
          router.push('/dashboard');
        }, 100);
      }
    }
  }, [router]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
      <div className="max-w-md mx-auto text-center p-8">
        <div className="mb-8">
          <div className="w-20 h-20 bg-indigo-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Digital Marketing Portal</h1>
          <p className="text-gray-600">Your comprehensive marketing management solution</p>
        </div>
        
        <div className="space-y-4">
          <div className="flex items-center justify-center space-x-2 text-sm text-gray-500">
            <div className="w-2 h-2 bg-indigo-600 rounded-full animate-pulse"></div>
            <span>Redirecting to dashboard...</span>
          </div>
          
          <div className="pt-4">
            <Link 
              href="/dashboard" 
              className="inline-flex items-center px-6 py-3 border border-transparent text-base font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 transition-colors duration-200"
            >
              Go to Dashboard
            </Link>
          </div>
        </div>
        
        <div className="mt-8 text-xs text-gray-400">
          <p>Features: Calendar Management • Client Management • File Processing • Reports</p>
        </div>
      </div>
    </div>
  );
}
