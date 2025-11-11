import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '../../../../../../lib/supabaseAdmin';
import { createNotificationsForEvent } from '../../../../../../lib/notify';

// PUT /api/upload/approve/[uploadId] - Approve or disapprove an upload
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ uploadId: string }> }
) {
  try {
    const { uploadId } = await params;
    const authHeader = request.headers.get('authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabaseAdmin.auth.getUser(token);
    if (authError || !currentUser) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    // Get user role to check permissions
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    const userRole = userData.role;

    // Only IT_ADMIN and AGENCY_ADMIN can approve/disapprove
    if (userRole !== 'IT_ADMIN' && userRole !== 'AGENCY_ADMIN') {
      return NextResponse.json({ error: 'Unauthorized: Only IT Admin and Agency Admin can approve uploads' }, { status: 403 });
    }

    const body = await request.json();
    const { approved, comment } = body;

    if (typeof approved !== 'boolean') {
      return NextResponse.json({ error: 'Missing or invalid approved field' }, { status: 400 });
    }

    // Update the approval status in the database
    const { data: uploadRecord, error: updateError } = await supabaseAdmin
      .from('post_uploads')
      .update({ 
        approved: approved,
        updated_at: new Date().toISOString()
      })
      .eq('id', uploadId)
      .select()
      .single();

    if (updateError || !uploadRecord) {
      console.error('Error updating approval:', updateError);
      return NextResponse.json({ error: 'Failed to update approval status' }, { status: 500 });
    }

    // Notify approval/disapproval
    try {
      await createNotificationsForEvent({
        type: 'APPROVAL',
        clientId: uploadRecord.client,
        entryId: uploadRecord.entry_id || null,
        actorUserId: currentUser.id,
        title: approved ? 'Post approved' : 'Post disapproved',
        body: comment ? String(comment) : (approved ? 'A post was approved' : 'A post was disapproved'),
        metadata: { route: `/dashboard` }
      });
    } catch (e) {
      console.error('Notify approval failed:', e);
    }

    return NextResponse.json({ success: true, upload: uploadRecord }, { status: 200 });

  } catch (error: any) {
    console.error('Error in PUT /api/upload/approve/[uploadId]:', error);
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 });
  }
}
