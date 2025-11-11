import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '../../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';

// GET /api/users/activity-logs - Get activity logs
export async function GET(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    // Get current user's role using admin client to bypass RLS
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData || userData.role !== 'IT_ADMIN') {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Get query parameters
    const { searchParams } = new URL(request.url);
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const action = searchParams.get('action');

    // Build query using admin client to bypass RLS
    let query = supabaseAdmin
      .from('activity_logs')
      .select(`
        *,
        users!activity_logs_user_id_fkey(first_name, last_name, email)
      `)
      .order('timestamp', { ascending: false })
      .range(offset, offset + limit - 1);

    if (action) {
      query = query.eq('action', action);
    }

    const { data: logs, error } = await query;

    if (error) {
      console.error('Error fetching activity logs:', error);
      return NextResponse.json({ error: 'Failed to fetch activity logs' }, { status: 500 });
    }

    return NextResponse.json({ logs: logs || [] });
  } catch (error) {
    console.error('Error in GET /api/users/activity-logs:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// POST /api/users/activity-logs - Create activity log
export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    const body = await request.json();
    const { action, targetUserId, details } = body;

    if (!action || !targetUserId) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    // Get IP address and user agent from request
    const ipAddress = request.headers.get('x-forwarded-for') || 
                     request.headers.get('x-real-ip') || 
                     '127.0.0.1';
    const userAgent = request.headers.get('user-agent') || 'Digital Marketing Portal';

    // Create activity log using admin client to bypass RLS
    const { data: log, error } = await supabaseAdmin
      .from('activity_logs')
      .insert([{
        user_id: currentUser.id,
        action,
        target_user_id: targetUserId,
        details,
        timestamp: new Date().toISOString(),
        ip_address: ipAddress,
        user_agent: userAgent
      }])
      .select()
      .single();

    if (error) {
      console.error('Error creating activity log:', error);
      return NextResponse.json({ error: 'Failed to create activity log' }, { status: 500 });
    }

    return NextResponse.json(log, { status: 201 });
  } catch (error) {
    console.error('Error in POST /api/users/activity-logs:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
