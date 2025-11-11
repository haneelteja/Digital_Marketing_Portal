'use client';

import React, { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { supabase } from '../../../lib/supabaseClient';

type NotificationItem = {
  id: string;
  type: 'POST_ADDED' | 'UPLOAD' | 'COMMENT' | 'APPROVAL' | 'PUBLISHED';
  title: string;
  body: string;
  is_read: boolean;
  created_at: string;
  metadata?: { route?: string } | null;
};

export function NotificationsBell() {
  const [items, setItems] = useState<NotificationItem[]>([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement | null>(null);
  const router = useRouter();

  async function load() {
    try {
      setLoading(true);
      setError(null);
      
      // Get Supabase session token
      const { data: { session }, error: sessionError } = await supabase.auth.getSession();
      if (sessionError || !session) {
        setError(null); // Silently fail if not authenticated
        setItems([]);
        setLoading(false);
        return;
      }

      const res = await fetch(`/api/notifications?unreadOnly=true&limit=20`, {
        headers: {
          'Authorization': `Bearer ${session.access_token}`
        },
      });
      
      if (!res.ok) {
        if (res.status === 401) {
          // Unauthorized - clear error and items
          setError(null);
          setItems([]);
        } else {
          throw new Error(`HTTP ${res.status}`);
        }
        return;
      }
      
      const data = await res.json();
      setItems(data.notifications || []);
    } catch (e) {
      console.warn('Failed to load notifications:', e);
      setError(null); // Don't show error to user, just fail silently
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  // Poll every 30s
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  // Close on outside click
  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    if (open) document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const unread = items.filter((i) => !i.is_read).length;

  async function markAllRead() {
    try {
      if (items.length === 0) return;
      
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) return;

      const ids = items.map((i) => i.id);
      await fetch('/api/notifications', {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session.access_token}`
        },
        body: JSON.stringify({ ids }),
      });
      setItems((prev) => prev.map((i) => ({ ...i, is_read: true })));
    } catch (e) {
      console.warn('Failed to mark notifications as read:', e);
    }
  }

  async function handleClickItem(item: NotificationItem) {
    if (item.metadata?.route) {
      router.push(item.metadata.route);
    } else {
      router.push('/dashboard');
    }
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (session) {
        await fetch('/api/notifications', {
          method: 'PUT',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${session.access_token}`
          },
          body: JSON.stringify({ ids: [item.id] }),
        });
        setItems((prev) => prev.map((i) => (i.id === item.id ? { ...i, is_read: true } : i)));
      }
    } catch (e) {
      console.warn('Failed to mark notification as read:', e);
    }
    setOpen(false);
  }

  return (
    <div className="relative" ref={ref}>
      <button
        aria-label="Notifications"
        className="relative inline-flex items-center justify-center w-10 h-10 rounded-full hover:bg-gray-100"
        onClick={() => setOpen((v) => !v)}
      >
        <svg className="w-6 h-6 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6 6 0 10-12 0v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        {unread > 0 && (
          <span className="absolute -top-1 -right-1 bg-red-600 text-white text-xs rounded-full px-1.5 py-0.5">
            {unread > 99 ? '99+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-80 bg-white border border-gray-200 rounded-lg shadow-lg z-50">
          <div className="px-4 py-2 border-b flex items-center justify-between">
            <div className="font-semibold text-gray-800">Notifications</div>
            <button onClick={markAllRead} className="text-sm text-indigo-600 hover:text-indigo-800">Mark all read</button>
          </div>
          {loading ? (
            <div className="p-4 text-sm text-gray-500">Loading...</div>
          ) : error ? (
            <div className="p-4 text-sm text-red-600">{error}</div>
          ) : items.length === 0 ? (
            <div className="p-4 text-sm text-gray-500">No new notifications</div>
          ) : (
            <ul className="max-h-96 overflow-y-auto">
              {items.map((n) => (
                <li key={n.id}>
                  <button
                    onClick={() => handleClickItem(n)}
                    className={`w-full text-left px-4 py-3 hover:bg-gray-50 ${n.is_read ? 'text-gray-600' : 'bg-indigo-50 text-indigo-900'}`}
                  >
                    <div className="text-sm font-medium">{n.title}</div>
                    <div className="text-xs opacity-80">{n.body}</div>
                    <div className="text-[11px] text-gray-400 mt-1">{new Date(n.created_at).toLocaleString()}</div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}


