import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '../../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';

// GET /api/upload/[entryId] - Get all uploads for a calendar entry
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ entryId: string }> }
) {
  try {
    const { entryId } = await params;
    const authHeader = request.headers.get('authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    // Get uploads for this calendar entry using admin client to bypass RLS
    const { data: uploads, error } = await supabaseAdmin
      .from('post_uploads')
      .select('*')
      .eq('calendar_entry_id', entryId)
      .order('option_number', { ascending: true });

    if (error) {
      console.error('Error fetching uploads:', error);
      return NextResponse.json({ error: 'Failed to fetch uploads' }, { status: 500 });
    }

    return NextResponse.json({ uploads: uploads || [] });
  } catch (error) {
    console.error('Error in GET /api/upload/[entryId]:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}



