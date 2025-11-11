import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { createNotificationsForEvent } from '../../../../lib/notify';
import { ok, created, badRequest, unauthorized, serverError, notFound } from '../../../../lib/apiResponse';
import { logger } from '../../../utils/logger';

type UserRole = 'IT_ADMIN' | 'AGENCY_ADMIN' | 'CLIENT' | 'DESIGNER';

interface DbUser {
  role: UserRole;
  assigned_clients: string[] | string | null;
  client_id: string | null;
}

interface DbCalendarEntry {
  id: string;
  date: string;
  client: string;
  post_type: string;
  post_content: string;
  hashtags: string | null;
  campaign_priority: string | null;
  created_at: string;
}

// GET /api/calendar-entries?start=YYYY-MM-DD&end=YYYY-MM-DD
export async function GET(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    const { searchParams } = new URL(request.url);
    const start = searchParams.get('start');
    const end = searchParams.get('end');

    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients, client_id')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return notFound('User not found');
    }

    let query = supabaseAdmin
      .from('calendar_entries')
      .select('id, date, client, post_type, post_content, hashtags, campaign_priority, created_at');

    if (start) query = query.gte('date', start);
    if (end) query = query.lte('date', end);

    // Declare entries variable in outer scope so it's accessible after the if/else blocks
    let entries: DbCalendarEntry[] | null = null;

    if ((userData as DbUser).role === 'AGENCY_ADMIN' || (userData as DbUser).role === 'DESIGNER') {
      // Normalize assigned_clients -> array of UUID strings
      let ids: string[] = [];
      const raw = (userData as DbUser).assigned_clients;
      if (Array.isArray(raw)) {
        ids = raw.filter((v): v is string => typeof v === 'string' && v.trim().length > 0);
      } else if (typeof raw === 'string' && raw.trim().length > 0) {
        ids = raw.split(',').map((s) => s.trim()).filter(Boolean);
      }

      const roleLabel = (userData as DbUser).role === 'DESIGNER' ? 'DESIGNER' : 'AGENCY_ADMIN';
      logger.debug(`${roleLabel} user assigned clients`, {
        component: 'GET /api/calendar-entries',
        userId: currentUser.id,
        role: roleLabel,
        assignedClientsCount: ids.length,
      });
      
      if (ids.length === 0) {
        logger.warn(`${roleLabel} user has no assigned clients`, {
          component: 'GET /api/calendar-entries',
          userId: currentUser.id,
          role: roleLabel,
        });
        return ok({ entries: [] });
      }
      query = query.in('client', ids);
    } else if ((userData as DbUser).role === 'CLIENT') {
      // Normalize assigned_clients -> array of UUID strings or company names
      // Use Set to ensure uniqueness and combine assigned_clients with client_id
      const identifiersSet = new Set<string>();
      const raw = (userData as DbUser).assigned_clients;
      
      // Process assigned_clients first
      if (raw) {
        if (Array.isArray(raw)) {
          raw.filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
            .forEach(id => identifiersSet.add(id.trim()));
        } else if (typeof raw === 'string' && raw.trim().length > 0) {
          raw.split(',').map((s) => s.trim()).filter(Boolean)
            .forEach(id => identifiersSet.add(id));
        }
      }
      
      // Also include client_id if it exists (legacy support and to ensure all associated clients are included)
      if ((userData as DbUser).client_id) {
        const clientId = (userData as DbUser).client_id as string;
        if (clientId.trim().length > 0) {
          identifiersSet.add(clientId.trim());
        }
      }

      const identifiers = Array.from(identifiersSet);
      
      logger.debug('CLIENT user assigned clients', {
        component: 'GET /api/calendar-entries',
        userId: currentUser.id,
        role: 'CLIENT',
        identifiersCount: identifiers.length,
        identifiers,
        assigned_clients: raw,
        client_id: (userData as DbUser).client_id,
      });

      if (identifiers.length === 0) {
        logger.warn('CLIENT user has no assigned clients', {
          component: 'GET /api/calendar-entries',
          userId: currentUser.id,
          role: 'CLIENT',
        });
        return ok({ entries: [] });
      }

      // Separate UUIDs from potential company names
      const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      const potentialUuids = identifiers.filter(id => uuidPattern.test(id));
      const potentialNames = identifiers.filter(id => !uuidPattern.test(id));

      // Fetch clients by UUIDs
      const clientUuids: string[] = [];
      const clientNames: string[] = [];
      
      if (potentialUuids.length > 0) {
        const { data: clientDataByUuid, error: clientDataError } = await supabaseAdmin
          .from('clients')
          .select('id, company_name')
          .in('id', potentialUuids);
        
        if (!clientDataError && clientDataByUuid) {
          clientDataByUuid.forEach((c: { id: string; company_name: string }) => {
            clientUuids.push(c.id);
            clientNames.push(c.company_name);
          });
        }
      }

      // Fetch clients by company names (case-insensitive exact match)
      if (potentialNames.length > 0) {
        // Query all clients and filter by exact match (case-insensitive)
        // This handles cases where company names might have slight variations
        const { data: allClients, error: allClientsError } = await supabaseAdmin
          .from('clients')
          .select('id, company_name')
          .is('deleted_at', null);
        
        if (!allClientsError && allClients) {
          logger.debug('Searching for client names', {
            component: 'GET /api/calendar-entries',
            userId: currentUser.id,
            potentialNamesCount: potentialNames.length,
            totalClientsCount: (allClients as any[]).length,
          });
          potentialNames.forEach(searchName => {
            const normalizedSearch = searchName.toLowerCase().trim();
            // Find ALL clients with matching company name (case-insensitive)
            // This handles cases where there are duplicate client records with the same company name
            const matchedClients = (allClients as { id: string; company_name: string }[]).filter(
              c => c.company_name.toLowerCase().trim() === normalizedSearch
            );
            
            if (matchedClients.length > 0) {
              logger.debug('Matched client name', {
                component: 'GET /api/calendar-entries',
                userId: currentUser.id,
                searchName,
                matchedCount: matchedClients.length,
                matchedClients: matchedClients.map(c => `${c.company_name} (${c.id})`),
              });
              matchedClients.forEach(matchedClient => {
                if (!clientUuids.includes(matchedClient.id)) {
                  clientUuids.push(matchedClient.id);
                }
                if (!clientNames.includes(matchedClient.company_name)) {
                  clientNames.push(matchedClient.company_name);
                }
              });
            } else {
              console.warn(`[CLIENT] WARNING: Could not find client with name "${searchName}" - will try to query calendar_entries directly with this name`);
            }
          });
        } else if (allClientsError) {
          console.error(`[CLIENT] Error fetching all clients:`, allClientsError);
        }
        
        // Also find all clients matching the resolved company names (to catch duplicates)
        // This ensures we query for entries even if they're stored with a different UUID for the same company
        // Reuse the allClients query from above if available
        if (clientNames.length > 0 && allClients) {
          clientNames.forEach(name => {
            const normalizedName = name.toLowerCase().trim();
            const matchingClients = (allClients as { id: string; company_name: string }[]).filter(
              c => c.company_name.toLowerCase().trim() === normalizedName
            );
            matchingClients.forEach(matchingClient => {
              if (!clientUuids.includes(matchingClient.id)) {
                console.warn(`[CLIENT] Found additional client UUID "${matchingClient.id}" for company "${name}" (duplicate client record)`);
                clientUuids.push(matchingClient.id);
              }
            });
          });
        }
      }

      // Combine all identifiers for querying calendar_entries
      // Use both UUIDs and company names to handle legacy data in calendar_entries
      // The calendar_entries table might have entries with client stored as either UUID or company name
      const allClientIdentifiers = [...new Set([...clientUuids, ...clientNames, ...potentialNames])];
      
      console.warn(`[CLIENT] Resolved ${clientUuids.length} UUIDs and ${clientNames.length} names from ${identifiers.length} identifiers`);
      console.warn(`[CLIENT] Client UUIDs:`, clientUuids);
      console.warn(`[CLIENT] Client Names:`, clientNames);
      console.warn(`[CLIENT] Potential Names (from assigned_clients):`, potentialNames);
      console.warn(`[CLIENT] Querying calendar_entries with ${allClientIdentifiers.length} total identifiers:`, allClientIdentifiers);
      
      if (allClientIdentifiers.length > 0) {
        // Query calendar_entries using all identifiers (UUIDs + company names)
        // This handles both migrated entries (stored as UUIDs) and legacy entries (stored as names)
        // If we have both UUIDs and names, query separately to ensure we catch all entries
        // Supabase .in() might have issues with mixed types, so we'll combine results from separate queries
        let entriesByUuid: DbCalendarEntry[] = [];
        let entriesByName: DbCalendarEntry[] = [];
        let entriesByRawIdentifiers: DbCalendarEntry[] = [];
        
        // Query by UUIDs if we have them
        if (clientUuids.length > 0) {
          console.warn(`[CLIENT] Querying calendar_entries by ${clientUuids.length} UUIDs:`, clientUuids);
          let uuidQuery = supabaseAdmin
            .from('calendar_entries')
            .select('id, date, client, post_type, post_content, hashtags, campaign_priority, created_at')
            .in('client', clientUuids);
          if (start) uuidQuery = uuidQuery.gte('date', start);
          if (end) uuidQuery = uuidQuery.lte('date', end);
          
          const { data: uuidEntries, error: uuidError } = await uuidQuery.order('date', { ascending: true });
          if (!uuidError && uuidEntries) {
            entriesByUuid = uuidEntries as DbCalendarEntry[];
            console.warn(`[CLIENT] Found ${entriesByUuid.length} entries by UUID`);
            // Log which clients were found in the entries
            if (entriesByUuid.length > 0) {
              const clientsInEntries = [...new Set(entriesByUuid.map(e => e.client))];
              console.warn(`[CLIENT] Entries found for clients (by UUID):`, clientsInEntries);
              // Log each entry's client value to debug
              entriesByUuid.forEach((entry, idx) => {
                console.warn(`[CLIENT] Entry ${idx + 1}: client="${entry.client}", date="${entry.date}"`);
              });
            }
            // Also check what entries exist in the database for the date range (regardless of client filter)
            // This helps debug if entries exist but aren't matching the query
            const debugQuery = supabaseAdmin
              .from('calendar_entries')
              .select('id, date, client')
              .gte('date', start || '2000-01-01')
              .lte('date', end || '2100-12-31')
              .order('date', { ascending: true })
              .limit(100);
            const { data: allEntriesInRange, error: debugError } = await debugQuery;
            if (!debugError && allEntriesInRange) {
              const allClientsInRange = [...new Set((allEntriesInRange as any[]).map((e: any) => e.client))];
              console.warn(`[CLIENT] DEBUG: All clients found in calendar_entries for date range:`, allClientsInRange);
              console.warn(`[CLIENT] DEBUG: Total entries in date range: ${(allEntriesInRange as any[]).length}`);
              
              // Map client UUIDs to company names to identify which entries belong to which clients
              const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
              const clientUuidsInEntries = allClientsInRange.filter((c: string) => uuidPattern.test(c));
              if (clientUuidsInEntries.length > 0) {
                const { data: clientMapping, error: mappingError } = await supabaseAdmin
                  .from('clients')
                  .select('id, company_name')
                  .in('id', clientUuidsInEntries);
                if (!mappingError && clientMapping) {
                  const mapping = (clientMapping as any[]).reduce((acc: Record<string, string>, c: any) => {
                    acc[c.id] = c.company_name;
                    return acc;
                  }, {});
                  console.warn(`[CLIENT] DEBUG: Client UUID to company name mapping:`, mapping);
                  
                  // Check if any of these clients match our assigned client names (case-insensitive)
                  // This handles cases where calendar entries are stored with a different UUID for the same client name
                  const normalizedAssignedNames = new Set(clientNames.map(n => n.toLowerCase().trim()));
                  const matchingClientUuids: string[] = [];
                  
                  Object.entries(mapping).forEach(([uuid, name]) => {
                    const normalizedName = String(name || '').toLowerCase().trim();
                    // Check if this client name matches any of our assigned client names (case-insensitive)
                    if (normalizedAssignedNames.has(normalizedName)) {
                      if (!clientUuids.includes(uuid)) {
                        matchingClientUuids.push(uuid);
                        console.warn(`[CLIENT] DEBUG: Found calendar entries for assigned client "${name}" with different UUID "${uuid}" - will include in query`);
                      }
                    }
                  });
                  
                  // Add matching UUIDs to our query list if we found any
                  if (matchingClientUuids.length > 0) {
                    clientUuids.push(...matchingClientUuids);
                    console.warn(`[CLIENT] DEBUG: Added ${matchingClientUuids.length} additional UUIDs to query:`, matchingClientUuids);
                    
                    // Query again with the additional UUIDs to get their entries
                    let additionalUuidQuery = supabaseAdmin
                      .from('calendar_entries')
                      .select('id, date, client, post_type, post_content, hashtags, campaign_priority, created_at')
                      .in('client', matchingClientUuids);
                    if (start) additionalUuidQuery = additionalUuidQuery.gte('date', start);
                    if (end) additionalUuidQuery = additionalUuidQuery.lte('date', end);
                    
                    const { data: additionalEntries, error: additionalError } = await additionalUuidQuery.order('date', { ascending: true });
                    if (!additionalError && additionalEntries) {
                      const additionalEntriesArray = additionalEntries as DbCalendarEntry[];
                      // Add to entriesByUuid, avoiding duplicates
                      const existingIds = new Set(entriesByUuid.map(e => e.id));
                      additionalEntriesArray.forEach(entry => {
                        if (!existingIds.has(entry.id)) {
                          entriesByUuid.push(entry);
                        }
                      });
                      console.warn(`[CLIENT] Found ${additionalEntriesArray.length} additional entries for matching UUIDs (total now: ${entriesByUuid.length})`);
                    }
                  }
                  
                  // Also check for entries that might be stored as company names (not UUIDs)
                  const nonUuidClients = allClientsInRange.filter((c: string) => !uuidPattern.test(c));
                  if (nonUuidClients.length > 0) {
                    console.warn(`[CLIENT] DEBUG: Found ${nonUuidClients.length} entries stored as company names (not UUIDs):`, nonUuidClients);
                    // Check if any of these match our assigned client names (case-insensitive)
                    const matchingNameEntries = nonUuidClients.filter((name: string) => {
                      const normalized = String(name || '').toLowerCase().trim();
                      return normalizedAssignedNames.has(normalized);
                    });
                    if (matchingNameEntries.length > 0) {
                      console.warn(`[CLIENT] DEBUG: Found entries stored as company names matching assigned clients:`, matchingNameEntries);
                    }
                  }
                }
              }
              // Check if our target UUIDs appear in the database at all
              clientUuids.forEach(uuid => {
                const entriesForThisUuid = (allEntriesInRange as any[]).filter((e: any) => e.client === uuid);
                console.warn(`[CLIENT] DEBUG: Found ${entriesForThisUuid.length} entries in DB for UUID "${uuid}"`);
              });
              
              // Check for entries for our target UUIDs across ALL dates (not just date range)
              // This helps determine if entries exist but are outside the queried range
              for (const uuid of clientUuids) {
                const { data: allTimeEntries, error: allTimeError } = await supabaseAdmin
                  .from('calendar_entries')
                  .select('id, date, client')
                  .eq('client', uuid)
                  .limit(10);
                if (!allTimeError && allTimeEntries && (allTimeEntries as any[]).length > 0) {
                  const dates = (allTimeEntries as any[]).map((e: any) => e.date).sort();
                  console.warn(`[CLIENT] DEBUG: Found ${(allTimeEntries as any[]).length} entries for UUID "${uuid}" across ALL dates. Sample dates:`, dates.slice(0, 5));
                } else {
                  console.warn(`[CLIENT] DEBUG: No entries found for UUID "${uuid}" across ALL dates in database`);
                }
              }
              
              // Also check what the actual company_name is in the clients table for our target UUIDs
              const { data: clientDetails, error: clientDetailsError } = await supabaseAdmin
                .from('clients')
                .select('id, company_name')
                .in('id', clientUuids);
              if (!clientDetailsError && clientDetails) {
                console.warn(`[CLIENT] DEBUG: Client details from database:`, (clientDetails as any[]).map((c: any) => ({ id: c.id, company_name: c.company_name })));
              }
            }
          } else if (uuidError) {
            console.error(`[CLIENT] Error querying by UUID:`, uuidError);
          }
        }
        
        // Query by names if we have them
        // Since calendar_entries might have entries stored with company names (case variations),
        // we need to query all entries in the date range and filter client-side for case-insensitive matching
        const nameIdentifiers = [...new Set([...clientNames, ...potentialNames])];
        if (nameIdentifiers.length > 0) {
          console.warn(`[CLIENT] Querying calendar_entries by ${nameIdentifiers.length} name identifiers (case-insensitive):`, nameIdentifiers);
          
          // Create a normalized set for case-insensitive matching
          const normalizedNames = new Set(nameIdentifiers.map(n => n.toLowerCase().trim()));
          
          // Query all entries in date range and filter by client name (case-insensitive)
          // This handles cases where entries are stored as "Biryanis and more" vs "Biryanis and More"
          let nameQuery = supabaseAdmin
            .from('calendar_entries')
            .select('id, date, client, post_type, post_content, hashtags, campaign_priority, created_at');
          if (start) nameQuery = nameQuery.gte('date', start);
          if (end) nameQuery = nameQuery.lte('date', end);
          
          const { data: allNameEntries, error: nameError } = await nameQuery.order('date', { ascending: true });
          if (!nameError && allNameEntries) {
            // Filter entries where client field matches any of our company names (case-insensitive)
            entriesByName = (allNameEntries as DbCalendarEntry[]).filter(entry => {
              const entryClientNormalized = String(entry.client || '').toLowerCase().trim();
              return normalizedNames.has(entryClientNormalized);
            });
            
            console.warn(`[CLIENT] Found ${entriesByName.length} entries by name (after case-insensitive filtering from ${(allNameEntries as any[]).length} total entries)`);
            // Log which clients were found in the entries
            if (entriesByName.length > 0) {
              const clientsInEntries = [...new Set(entriesByName.map(e => e.client))];
              console.warn(`[CLIENT] Entries found for clients (by name):`, clientsInEntries);
            }
          } else if (nameError) {
            console.error(`[CLIENT] Error querying by name:`, nameError);
          }
        }
        
        // Also try querying with the raw identifiers from assigned_clients directly
        // This catches cases where calendar_entries might be stored exactly as they appear in assigned_clients
        // Since calendar_entries.client is TEXT, we need to ensure we're querying with all possible formats
        if (identifiers.length > 0) {
          // Filter out identifiers we've already queried to avoid duplicates
          const alreadyQueried = new Set([...clientUuids, ...clientNames, ...potentialNames]);
          const uniqueRawIdentifiers = identifiers.filter(id => !alreadyQueried.has(id));
          
          if (uniqueRawIdentifiers.length > 0) {
            console.warn(`[CLIENT] Also querying calendar_entries by ${uniqueRawIdentifiers.length} unique raw identifiers from assigned_clients:`, uniqueRawIdentifiers);
            let rawQuery = supabaseAdmin
              .from('calendar_entries')
              .select('id, date, client, post_type, post_content, hashtags, campaign_priority, created_at')
              .in('client', uniqueRawIdentifiers);
            if (start) rawQuery = rawQuery.gte('date', start);
            if (end) rawQuery = rawQuery.lte('date', end);
            
            const { data: rawEntries, error: rawError } = await rawQuery.order('date', { ascending: true });
            if (!rawError && rawEntries) {
              entriesByRawIdentifiers = rawEntries as DbCalendarEntry[];
              console.warn(`[CLIENT] Found ${entriesByRawIdentifiers.length} entries by raw identifiers`);
              if (entriesByRawIdentifiers.length > 0) {
                const clientsInEntries = [...new Set(entriesByRawIdentifiers.map(e => e.client))];
                console.warn(`[CLIENT] Entries found for clients (by raw identifiers):`, clientsInEntries);
              }
            } else if (rawError) {
              console.error(`[CLIENT] Error querying by raw identifiers:`, rawError);
            }
          }
        }
        
        // Combine and deduplicate entries by id
        const entryMap = new Map<string, DbCalendarEntry>();
        [...entriesByUuid, ...entriesByName, ...entriesByRawIdentifiers].forEach(entry => {
          entryMap.set(entry.id, entry);
        });
        const combinedEntries = Array.from(entryMap.values()).sort((a, b) => a.date.localeCompare(b.date));
        
        console.warn(`[CLIENT] Combined ${combinedEntries.length} unique entries from ${entriesByUuid.length} UUID entries, ${entriesByName.length} name entries, and ${entriesByRawIdentifiers.length} raw identifier entries`);
        
        // Use combined entries for the rest of the processing
        // Skip the standard query execution and go directly to mapping
        entries = combinedEntries;
        
        // Log entries found per client for debugging
        if (entries && entries.length > 0) {
          const entriesByClient = (entries as DbCalendarEntry[]).reduce((acc: Record<string, number>, entry) => {
            acc[entry.client] = (acc[entry.client] || 0) + 1;
            return acc;
          }, {});
          console.warn(`[CLIENT] Found ${entries.length} total entries across ${Object.keys(entriesByClient).length} clients:`, entriesByClient);
        }
      } else {
        console.warn(`[CLIENT] No valid client identifiers found after lookup, returning empty array`);
        return ok({ entries: [] });
      }
    }

    // For IT_ADMIN or other roles, or if CLIENT didn't set entries, use the standard query
    if (!entries) {
      const { data: queryEntries, error: queryError } = await query.order('date', { ascending: true });
      if (queryError) {
        console.error('Error fetching calendar entries:', queryError);
      return serverError('Failed to fetch entries');
      }
      entries = queryEntries as DbCalendarEntry[] | null;
    }
    
    if (!entries) {
      entries = [];
    }

    // Fetch client names for mapping (for all roles)
    // Note: 'entries' variable is now available from either the CLIENT branch or the standard query
    // Handle both UUIDs and company names (legacy data) in calendar entries
    const uniqueClientValues = [...new Set((entries as DbCalendarEntry[] | null || []).map((e) => e.client).filter(Boolean))];
    let clientMap: Record<string, string> = {};
    
    if (uniqueClientValues.length > 0) {
      // Separate UUIDs from company names
      const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      const clientIds = uniqueClientValues.filter(v => uuidPattern.test(v));
      const clientNames = uniqueClientValues.filter(v => !uuidPattern.test(v));
      
      // Fetch client data for UUIDs
    if (clientIds.length > 0) {
      const { data: clients, error: clientsError } = await supabaseAdmin
        .from('clients')
        .select('id, company_name')
        .in('id', clientIds);
      
      if (!clientsError && clients) {
          (clients as { id: string; company_name: string }[]).forEach((client) => {
            clientMap[client.id] = client.company_name;
            // Also map company name to itself for consistency
            clientMap[client.company_name] = client.company_name;
          });
        }
      }
      
      // For entries already using company names, map them to themselves
      clientNames.forEach(name => {
        if (!clientMap[name]) {
          clientMap[name] = name;
        }
      });
    }

    // Map client UUIDs/names to client names in the entries
    const entriesWithClientNames = (entries as DbCalendarEntry[] | null || []).map((entry) => ({
      ...entry,
      client: clientMap[entry.client] || entry.client // Use mapped name if available, fallback to original value
    }));

    console.warn(`Fetched ${entriesWithClientNames?.length || 0} calendar entries for user ${currentUser.id} (${userData?.role})`);
    // Log unique clients found in entries for debugging
    const uniqueClientsInEntries = [...new Set(entriesWithClientNames?.map(e => e.client) || [])];
    if (uniqueClientsInEntries.length > 0) {
      console.warn(`[${userData?.role}] Entries found for clients:`, uniqueClientsInEntries);
    }
    
    // Add debug info for CLIENT role to help troubleshoot
    let debugInfo = undefined;
    if ((userData as DbUser).role === 'CLIENT') {
      debugInfo = {
        totalEntries: entriesWithClientNames?.length || 0,
        uniqueClientsInEntries: uniqueClientsInEntries,
        message: 'Check server terminal for detailed [CLIENT] logs'
      };
    }
    
    return ok({ entries: entriesWithClientNames || [], debug: debugInfo });
  } catch (e) {
    console.error('Error in GET /api/calendar-entries:', e);
    return serverError();
  }
}

export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    // Check user role - DESIGNER cannot create posts
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return unauthorized('User not found');
    }

    if ((userData as DbUser).role === 'DESIGNER') {
      return unauthorized('Designers cannot create posts. They can only edit existing post content.');
    }

    const body = await request.json();
    
    // Validate required fields
    const requiredFields = ['date', 'client', 'post_type'];
    const missingFields = requiredFields.filter(field => !body[field]);
    
    if (missingFields.length > 0) {
      return badRequest(`Missing required fields: ${missingFields.join(', ')}`);
    }

    console.warn(`[POST] Creating calendar entry by user ${currentUser.id}`);

    // Validate client exists and is not deleted to prevent posting to deleted clients
    const { data: clientRow, error: clientCheckError } = await supabaseAdmin
      .from('clients')
      .select('id, deleted_at')
      .eq('id', body.client)
      .single();

    if (clientCheckError || !clientRow) {
      return badRequest('Invalid client');
    }
    if ((clientRow as any).deleted_at) {
      return badRequest('Client is deleted. Cannot create new posts for this client.');
    }

    const { data, error } = await supabaseAdmin
      .from('calendar_entries')
      .insert(body)
      .select()
      .single();

    if (error) {
      console.error('Database error:', error);
      return serverError('Failed to create calendar entry');
    }

    // Fetch client name for the created entry
    let clientName = body.client;
    if (data.client) {
      const { data: clientData } = await supabaseAdmin
        .from('clients')
        .select('company_name')
        .eq('id', data.client)
        .is('deleted_at', null)
        .single();
      
      if (clientData) {
        clientName = clientData.company_name;
      }
    }

    // Return entry with client name instead of UUID
    const entryWithClientName = {
      ...data,
      client: clientName
    };

    console.warn(`[POST] Successfully created calendar entry ${data.id} for client`);

    // Fire notification for relevant users
    try {
      await createNotificationsForEvent({
        type: 'POST_ADDED',
        clientId: body.client,
        entryId: data.id,
        actorUserId: currentUser.id,
        title: 'New post added',
        body: `A new post was added for client ${clientName}`,
        metadata: { route: `/dashboard?month=${new Date(body.date).toISOString().slice(0,7)}` }
      });
    } catch (e) {
      console.error('Failed to create notifications:', e);
    }
    return created({ data: entryWithClientName });

  } catch (error) {
    console.error('API error:', error);
    return serverError();
  }
}
