import { NextRequest } from 'next/server';
import { supabase } from '../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError } from '../../../../lib/apiResponse';

// GET /api/notifications?unreadOnly=true&limit=20&since=ISO
export async function GET(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return unauthorized();

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) return unauthorized('Invalid token');

    const { searchParams } = new URL(request.url);
    const unreadOnly = searchParams.get('unreadOnly') === 'true';
    const since = searchParams.get('since');
    const limit = Math.min(parseInt(searchParams.get('limit') || '20', 10) || 20, 50);

    let query = supabaseAdmin
      .from('notifications')
      .select('id, client_id, entry_id, type, title, body, is_read, created_at, metadata')
      .eq('user_id', currentUser.id)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (unreadOnly) query = query.eq('is_read', false);
    if (since) query = query.gte('created_at', since);

    const { data, error } = await query;
    if (error) return serverError('Failed to fetch notifications');
    return ok({ notifications: data || [] });
  } catch {
    return serverError();
  }
}

// PUT /api/notifications -> { ids: string[] }
export async function PUT(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return unauthorized();
    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) return unauthorized('Invalid token');

    const body = await request.json();
    const ids: unknown = body?.ids;
    if (!Array.isArray(ids) || ids.length === 0 || !ids.every((id) => typeof id === 'string')) {
      return badRequest('Invalid ids');
    }

    const { error } = await supabaseAdmin
      .from('notifications')
      .update({ is_read: true })
      .in('id', ids as string[])
      .eq('user_id', currentUser.id);

    if (error) return serverError('Failed to mark notifications as read');
    return ok({ updated: ids.length });
  } catch {
    return serverError();
  }
}


