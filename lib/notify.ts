import { supabaseAdmin } from './supabaseAdmin';

type NotificationType = 'POST_ADDED' | 'UPLOAD' | 'COMMENT' | 'APPROVAL' | 'PUBLISHED';

type CreateEvent = {
  type: NotificationType;
  clientId: string;
  entryId?: string | null;
  actorUserId: string;
  title: string;
  body: string;
  metadata?: Record<string, unknown>;
};

// Fetch target users for clientId by role rules
async function getTargetUserIds(clientId: string): Promise<string[]> {
  const ids = new Set<string>();

  // IT Admins → all
  const { data: itAdmins } = await supabaseAdmin
    .from('users')
    .select('id, role');
  (itAdmins || []).forEach((u: any) => { if (u.role === 'IT_ADMIN') ids.add(u.id); });

  // Agency Admins assigned to this client
  const { data: agencyAdmins } = await supabaseAdmin
    .from('users')
    .select('id, role, assigned_clients')
    .eq('role', 'AGENCY_ADMIN');
  (agencyAdmins || []).forEach((u: any) => {
    const raw = u.assigned_clients;
    let assigned: string[] = [];
    if (Array.isArray(raw)) assigned = raw; else if (typeof raw === 'string') assigned = raw.split(',').map((s: string) => s.trim());
    if (assigned.includes(clientId)) ids.add(u.id);
  });

  // Clients assigned to this client
  const { data: clients } = await supabaseAdmin
    .from('users')
    .select('id, role, assigned_clients, client_id')
    .eq('role', 'CLIENT');
  (clients || []).forEach((u: any) => {
    const arr = Array.isArray(u.assigned_clients) ? u.assigned_clients : (typeof u.assigned_clients === 'string' ? u.assigned_clients.split(',').map((s: string) => s.trim()) : []);
    if (arr.includes(clientId) || u.client_id === clientId) ids.add(u.id);
  });

  return Array.from(ids);
}

export async function createNotificationsForEvent(evt: CreateEvent): Promise<number> {
  const targetUserIds = await getTargetUserIds(evt.clientId);
  if (targetUserIds.length === 0) return 0;

  const rows = targetUserIds.map((uid) => ({
    user_id: uid,
    client_id: evt.clientId,
    entry_id: evt.entryId ?? null,
    type: evt.type,
    title: evt.title,
    body: evt.body,
    metadata: evt.metadata ?? null,
  }));

  const { error } = await supabaseAdmin.from('notifications').insert(rows);
  if (error) {
    // Swallow errors to avoid breaking primary flows; log server-side
    console.error('Failed to insert notifications:', error);
    return 0;
  }
  return rows.length;
}


