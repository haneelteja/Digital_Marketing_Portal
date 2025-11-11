'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { User } from '../types/user';
import { supabase } from '../../lib/supabaseClient';
import { useClientCache } from './ClientCacheProvider';

interface AssignedClientsProps {
  currentUser: User | null;
  entriesByDate?: Record<string, Array<{ client: string; date: string; post_type?: string; campaign_priority?: string }>>;
  onClientClick?: (clientId: string, clientName: string) => void;
}

interface ClientInfo {
  id: string;
  companyName: string;
  email?: string;
  postCount?: number;
  campaignCount?: number;
  lastActivity?: string;
}

export const AssignedClients: React.FC<AssignedClientsProps> = ({ currentUser, entriesByDate = {}, onClientClick }) => {
  const [loading, setLoading] = useState(true);
  const [clientDetails, setClientDetails] = useState<ClientInfo[]>([]);
  const { clients: clientCache = [] } = useClientCache();

  // Calculate post counts for each client
  const clientPostCounts = useMemo(() => {
    const counts: Record<string, { posts: number; campaigns: number; lastActivity?: string }> = {};
    const allEntries = Object.values(entriesByDate).flat();
    const safeClientCache = Array.isArray(clientCache) ? clientCache : [];
    
    // Create a map of client names to IDs for matching
    const nameToIdMap = new Map<string, string>();
    safeClientCache.forEach(client => {
      const name = client.company_name || client.companyName;
      if (name && client.id) {
        nameToIdMap.set(name.toLowerCase(), client.id);
      }
    });
    
    allEntries.forEach(entry => {
      if (entry.client) {
        // Try to match by ID first, then by name
        let clientIdentifier = entry.client;
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entry.client);
        
        // If it's not a UUID, try to find the ID by name
        if (!isUUID) {
          const matchedId = nameToIdMap.get(entry.client.toLowerCase());
          if (matchedId) {
            clientIdentifier = matchedId;
          }
        }
        
        if (!counts[clientIdentifier]) {
          counts[clientIdentifier] = { posts: 0, campaigns: 0 };
        }
        counts[clientIdentifier].posts += 1;
        
        // Check if it's a campaign (has campaign_priority)
        if (entry.campaign_priority) {
          counts[clientIdentifier].campaigns += 1;
        }
        
        // Track last activity date
        if (entry.date) {
          const entryDate = new Date(entry.date);
          const lastActivityDate = counts[clientIdentifier].lastActivity 
            ? new Date(counts[clientIdentifier].lastActivity!) 
            : null;
          if (!lastActivityDate || entryDate > lastActivityDate) {
            counts[clientIdentifier].lastActivity = entry.date;
          }
        }
      }
    });
    
    return counts;
  }, [entriesByDate, clientCache]);

  // Get assigned client IDs from currentUser
  const assignedClientIds = useMemo(() => {
    if (!currentUser) {
      console.warn('[AssignedClients] No currentUser provided');
      return [];
    }
    
    // For IT_ADMIN, show all clients
    if (currentUser.role === 'IT_ADMIN') {
      const safeClientCache = Array.isArray(clientCache) ? clientCache : [];
      const allClientIds = safeClientCache.map(c => c.id).filter(Boolean);
      console.log('[AssignedClients] IT_ADMIN - showing all clients:', allClientIds.length);
      return allClientIds;
    }
    
    // For AGENCY_ADMIN and CLIENT, show assigned clients
    const assignedFromField = currentUser.assignedClients || [];
    const legacyClientId = currentUser.clientId;
    
    // Combine assigned clients and legacy client_id
    const allAssignedIds = new Set<string>();
    
    // Add assigned clients from the array
    if (Array.isArray(assignedFromField) && assignedFromField.length > 0) {
      assignedFromField.forEach(id => {
        if (typeof id === 'string' && id.trim().length > 0) {
          allAssignedIds.add(id.trim());
        }
      });
    }
    
    // Add legacy client_id if it exists
    if (legacyClientId && typeof legacyClientId === 'string' && legacyClientId.trim().length > 0) {
      allAssignedIds.add(legacyClientId.trim());
    }
    
    const result = Array.from(allAssignedIds);
    
    console.log('[AssignedClients] Assigned client IDs:', {
      role: currentUser.role,
      assignedClients: assignedFromField,
      legacyClientId,
      normalizedResult: result,
      count: result.length
    });
    
    return result;
  }, [currentUser, clientCache]);

  // Fetch client details whenever assignedClientIds or clientCache changes
  useEffect(() => {
    const fetchClientDetails = async () => {
      // For IT_ADMIN, directly use all clients from cache
      if (currentUser?.role === 'IT_ADMIN') {
        const safeClientCache = Array.isArray(clientCache) ? clientCache : [];
        console.log('[AssignedClients] IT_ADMIN - Total clients in cache:', safeClientCache.length);
        
        if (safeClientCache.length === 0) {
          setClientDetails([]);
          setLoading(true); // Keep loading if cache is empty
          return;
        }
        
        // Map all clients from cache directly
        const allClients: ClientInfo[] = safeClientCache.map(client => {
          const counts = clientPostCounts[client.id] || { posts: 0, campaigns: 0 };
          // Also check by company name for backward compatibility
          const countsByName = Object.entries(clientPostCounts).find(([id]) => {
            const cacheClient = safeClientCache.find(c => c.id === id);
            return cacheClient && (cacheClient.company_name === (client.company_name || client.companyName) || 
                   cacheClient.companyName === (client.company_name || client.companyName));
          });
          const finalCounts = countsByName ? clientPostCounts[countsByName[0]] : counts;
          
          return {
            id: client.id,
            companyName: client.company_name || client.companyName || 'Unknown Client',
            email: client.email,
            postCount: finalCounts.posts,
            campaignCount: finalCounts.campaigns,
            lastActivity: finalCounts.lastActivity
          };
        });
        
        setClientDetails(allClients.sort((a, b) => a.companyName.localeCompare(b.companyName)));
        setLoading(false);
        console.log('[AssignedClients] IT_ADMIN - Loaded all clients:', allClients.length);
        return;
      }
      
      // For other roles, use assigned client IDs
      if (assignedClientIds.length === 0) {
        setClientDetails([]);
        setLoading(false);
        return;
      }

      setLoading(true);
      try {
        // First, try to get clients from cache
        const cachedClients: ClientInfo[] = [];
        const missingIds: string[] = [];
        const safeClientCache = Array.isArray(clientCache) ? clientCache : [];

        assignedClientIds.forEach(clientId => {
          const cachedClient = safeClientCache.find(c => c?.id === clientId);
          if (cachedClient) {
            cachedClients.push({
              id: cachedClient.id,
              companyName: cachedClient.company_name || cachedClient.companyName || 'Unknown Client',
              email: cachedClient.email
            });
          } else {
            missingIds.push(clientId);
          }
        });

        // If all clients found in cache, use them
        if (missingIds.length === 0) {
          // Enrich with post counts
          const enrichedClients = cachedClients.map(client => {
            const counts = clientPostCounts[client.id] || { posts: 0, campaigns: 0 };
            // Also check by company name for backward compatibility
            const countsByName = Object.entries(clientPostCounts).find(([id]) => {
              const cacheClient = safeClientCache.find(c => c.id === id);
              return cacheClient && (cacheClient.company_name === client.companyName || cacheClient.companyName === client.companyName);
            });
            const finalCounts = countsByName ? clientPostCounts[countsByName[0]] : counts;
            
            return {
              ...client,
              postCount: finalCounts.posts,
              campaignCount: finalCounts.campaigns,
              lastActivity: finalCounts.lastActivity
            };
          });
          
          setClientDetails(enrichedClients.sort((a, b) => a.companyName.localeCompare(b.companyName)));
          setLoading(false);
          return;
        }

        // Fetch missing clients from API
        const { data: { session } } = await supabase.auth.getSession();
        if (!session?.access_token) {
          setClientDetails(cachedClients);
          setLoading(false);
          return;
        }

        const response = await fetch('/api/clients', {
          headers: {
            'Authorization': `Bearer ${session.access_token}`
          }
        });

        if (response.ok) {
          const json = await response.json();
          const allClients = json.data || [];
          
          // Map missing IDs to client details
          missingIds.forEach(clientId => {
            const client = allClients.find((c: any) => c.id === clientId);
            if (client) {
              const counts = clientPostCounts[clientId] || { posts: 0, campaigns: 0 };
              cachedClients.push({
                id: client.id,
                companyName: client.company_name || client.companyName || 'Unknown Client',
                email: client.email,
                postCount: counts.posts,
                campaignCount: counts.campaigns,
                lastActivity: counts.lastActivity
              });
            } else {
              // Client not found - still show the ID
              const counts = clientPostCounts[clientId] || { posts: 0, campaigns: 0 };
              cachedClients.push({
                id: clientId,
                companyName: 'Client Not Found',
                email: undefined,
                postCount: counts.posts,
                campaignCount: counts.campaigns,
                lastActivity: counts.lastActivity
              });
            }
          });

          // Enrich cached clients with post counts
          const enrichedClients = cachedClients.map(client => {
            if (client.postCount !== undefined) return client;
            const counts = clientPostCounts[client.id] || { posts: 0, campaigns: 0 };
            return {
              ...client,
              postCount: counts.posts,
              campaignCount: counts.campaigns,
              lastActivity: counts.lastActivity
            };
          });

          setClientDetails(enrichedClients.sort((a, b) => a.companyName.localeCompare(b.companyName)));
        } else {
          setClientDetails(cachedClients);
        }
      } catch (error) {
        console.error('Error fetching client details:', error);
        // Fallback to showing IDs if fetch fails
        setClientDetails(assignedClientIds.map(id => ({
          id,
          companyName: 'Loading...',
          email: undefined
        })));
      } finally {
        setLoading(false);
      }
    };

    fetchClientDetails();
  }, [assignedClientIds, clientCache, clientPostCounts, currentUser]);

  // Early returns to prevent rendering issues
  if (!currentUser) {
    return null;
  }

  const handleClientClick = (client: ClientInfo) => {
    if (onClientClick) {
      onClientClick(client.id, client.companyName);
    } else {
      // Default behavior: filter by client in dashboard
      // This could be enhanced to navigate to a client-specific view
      console.log('Navigate to client:', client.id, client.companyName);
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return null;
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    } catch {
      return null;
    }
  };

  return (
    <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="text-2xl">👥</div>
          <h3 className="text-lg font-semibold text-gray-900">Assigned Clients</h3>
        </div>
        {clientDetails.length > 0 && (
          <div className="text-sm text-gray-500">
            {clientDetails.length} {clientDetails.length === 1 ? 'client' : 'clients'}
          </div>
        )}
      </div>
      
      {loading ? (
        <div className="flex items-center justify-center py-8 flex-1">
          <div className="flex items-center gap-3">
            <div className="animate-spin rounded-full h-5 w-5 border-2 border-indigo-600 border-t-transparent"></div>
            <span className="text-gray-600">Loading clients...</span>
          </div>
        </div>
      ) : clientDetails.length === 0 ? (
        <div className="text-gray-500 text-sm py-8 text-center flex-1 flex items-center justify-center">
          {currentUser.role === 'IT_ADMIN' 
            ? 'No clients available' 
            : 'No clients assigned'}
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto max-h-[500px] pr-2 space-y-3">
          {clientDetails.map((client) => (
            <div
              key={client.id}
              onClick={() => handleClientClick(client)}
              className={`p-3 bg-gray-50 rounded-lg border border-gray-200 transition-all ${
                onClientClick 
                  ? 'cursor-pointer hover:border-indigo-300 hover:bg-indigo-50 hover:shadow-sm' 
                  : ''
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-gray-900 truncate">{client.companyName}</div>
                  {client.email && (
                    <div className="text-xs text-gray-500 mt-1 truncate">{client.email}</div>
                  )}
                  
                  {/* Post and Campaign Counts */}
                  <div className="flex items-center gap-4 mt-2 text-xs">
                    {(client.postCount !== undefined && client.postCount > 0) && (
                      <div className="flex items-center gap-1 text-gray-600">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        <span>{client.postCount} {client.postCount === 1 ? 'post' : 'posts'}</span>
                      </div>
                    )}
                    {(client.campaignCount !== undefined && client.campaignCount > 0) && (
                      <div className="flex items-center gap-1 text-indigo-600">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                        </svg>
                        <span>{client.campaignCount} {client.campaignCount === 1 ? 'campaign' : 'campaigns'}</span>
                      </div>
                    )}
                  </div>
                  
                  {/* Last Activity */}
                  {client.lastActivity && (
                    <div className="text-xs text-gray-400 mt-1">
                      Last activity: {formatDate(client.lastActivity)}
                    </div>
                  )}
                </div>
                <div className="flex-shrink-0 flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  {onClientClick && (
                    <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

