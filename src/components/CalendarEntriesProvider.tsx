'use client';

import React, { createContext, useContext, useState } from 'react';
import { supabase } from '../../lib/supabaseClient';

interface CalendarEntry {
  id: string;
  date: string;
  client: string;
  post_type: string;
  platform?: string;
  content?: string;
  image_url?: string;
  status?: string;
  campaign_priority?: string;
  post_content?: string;
  hashtags?: string;
  created_at: string;
  updated_at?: string;
}

interface CalendarEntriesContextType {
  entriesByDate: Record<string, CalendarEntry[]>;
  loading: boolean;
  refreshEntries: (cursor: Date) => Promise<void>;
  addEntry: (entry: Omit<CalendarEntry, 'id' | 'created_at'>) => Promise<void>;
  updateEntry: (id: string, updates: Partial<CalendarEntry>) => Promise<void>;
  deleteEntry: (id: string) => Promise<void>;
}

const CalendarEntriesContext = createContext<CalendarEntriesContextType>({
  entriesByDate: {},
  loading: false,
  refreshEntries: async () => {},
  addEntry: async () => {},
  updateEntry: async () => {},
  deleteEntry: async () => {},
});

export const CalendarEntriesProvider = ({ children }: { children: React.ReactNode }) => {
  const [entriesByDate, setEntriesByDate] = useState<Record<string, CalendarEntry[]>>({});
  const [loading, setLoading] = useState(false);
  const [cache, setCache] = useState<{data: Record<string, CalendarEntry[]>, timestamp: number, month: string} | null>(null);
  const CACHE_DURATION = 60000; // 1 minute cache

  const formatDateForDB = (date: Date): string => {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  };

  const refreshEntries = async (cursor: Date) => {
    const monthKey = `${cursor.getFullYear()}-${cursor.getMonth()}`;
    
    // Check cache first
    if (cache && 
        cache.month === monthKey && 
        Date.now() - cache.timestamp < CACHE_DURATION) {
      setEntriesByDate(cache.data);
      return;
    }

    setLoading(true);
    try {
      const monthStart = formatDateForDB(new Date(cursor.getFullYear(), cursor.getMonth(), 1));
      const monthEnd = formatDateForDB(new Date(cursor.getFullYear(), cursor.getMonth() + 1, 0));
      
      const { data, error } = await supabase
        .from('calendar_entries')
        .select('id, date, client, post_type, post_content, hashtags, campaign_priority, created_at, updated_at')
        .gte('date', monthStart)
        .lte('date', monthEnd)
        .order('date', { ascending: true });

      if (error) {
        console.error('Error loading calendar entries:', error);
        setEntriesByDate({});
        return;
      }

      const grouped: Record<string, CalendarEntry[]> = {};
      (data as CalendarEntry[] | null || []).forEach((row: CalendarEntry) => {
        const key = row.date;
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push(row);
      });

      setEntriesByDate(grouped);
      setCache({ data: grouped, timestamp: Date.now(), month: monthKey });
    } catch (error) {
      console.error('Error in refreshEntries:', error);
      setEntriesByDate({});
    } finally {
      setLoading(false);
    }
  };

  const addEntry = async (entry: Omit<CalendarEntry, 'id' | 'created_at'>) => {
    try {
      const { data, error } = await supabase
        .from('calendar_entries')
        .insert(entry)
        .select()
        .single();

      if (error) throw error;

      // Update local state
      setEntriesByDate(prev => {
        const newEntries = { ...prev };
        const key = entry.date;
        if (!newEntries[key]) newEntries[key] = [];
        newEntries[key] = [...newEntries[key], data];
        return newEntries;
      });

      // Invalidate cache
      setCache(null);
    } catch (error) {
      console.error('Error adding entry:', error);
      throw error;
    }
  };

  const updateEntry = async (id: string, updates: Partial<CalendarEntry>) => {
    try {
      const { data, error } = await supabase
        .from('calendar_entries')
        .update(updates)
        .eq('id', id)
        .select()
        .single();

      if (error) throw error;

      // Update local state
      setEntriesByDate(prev => {
        const newEntries = { ...prev };
        Object.keys(newEntries).forEach(date => {
          newEntries[date] = newEntries[date].map(entry => 
            entry.id === id ? { ...entry, ...data } : entry
          );
        });
        return newEntries;
      });

      // Invalidate cache
      setCache(null);
    } catch (error) {
      console.error('Error updating entry:', error);
      throw error;
    }
  };

  const deleteEntry = async (id: string) => {
    try {
      const { error } = await supabase
        .from('calendar_entries')
        .delete()
        .eq('id', id);

      if (error) throw error;

      // Update local state
      setEntriesByDate(prev => {
        const newEntries = { ...prev };
        Object.keys(newEntries).forEach(date => {
          newEntries[date] = newEntries[date].filter(entry => entry.id !== id);
        });
        return newEntries;
      });

      // Invalidate cache
      setCache(null);
    } catch (error) {
      console.error('Error deleting entry:', error);
      throw error;
    }
  };

  return (
    <CalendarEntriesContext.Provider value={{
      entriesByDate,
      loading,
      refreshEntries,
      addEntry,
      updateEntry,
      deleteEntry,
    }}>
      {children}
    </CalendarEntriesContext.Provider>
  );
};

export const useCalendarEntries = () => useContext(CalendarEntriesContext);
