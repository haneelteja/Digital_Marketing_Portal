import { NextRequest } from 'next/server';
import { supabase } from '../../../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError, notFound } from '../../../../../../lib/apiResponse';
import { logger } from '../../../../../utils/logger';

// POST /api/campaign-uploads/[id]/comments - Add a comment to an upload
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    const body = await request.json();
    const { commentText } = body;

    if (!commentText || !commentText.trim()) {
      return badRequest('Comment text is required');
    }

    // Get upload and verify access
    const { data: upload, error: uploadError } = await supabaseAdmin
      .from('campaign_uploads')
      .select(`
        *,
        campaign:campaign_id (
          id,
          client_id,
          assigned_users,
          created_by
        )
      `)
      .eq('id', id)
      .single();

    if (uploadError || !upload) {
      return notFound('Upload not found');
    }

    // Check if upload is approved - no new comments allowed after approval
    if (upload.approved) {
      return badRequest('Cannot add comments to approved uploads');
    }

    const campaign = (upload as any).campaign;

    // Get user role for access check
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return unauthorized('User not found');
    }

    const userRole = userData.role;
    const assignedClients = Array.isArray(userData.assigned_clients)
      ? userData.assigned_clients.filter((id): id is string => typeof id === 'string')
      : [];

    // Check access permissions
    const isAdmin = userRole === 'IT_ADMIN' || userRole === 'AGENCY_ADMIN';
    const isCreator = campaign.created_by === currentUser.id;
    const isAssigned = Array.isArray(campaign.assigned_users) && campaign.assigned_users.includes(currentUser.id);
    const hasClientAccess = campaign.client_id && (
      assignedClients.includes(campaign.client_id) ||
      assignedClients.some(clientId => clientId === campaign.client_id)
    );

    if (!isAdmin && !isCreator && !isAssigned && !hasClientAccess) {
      return unauthorized('You do not have access to comment on this upload');
    }

    // Add comment
    const { data: comment, error: commentError } = await supabaseAdmin
      .from('campaign_upload_comments')
      .insert([{
        campaign_upload_id: id,
        user_id: currentUser.id,
        comment_text: commentText.trim(),
        comment_type: 'feedback',
      }])
      .select(`
        *,
        users:user_id (
          email,
          first_name,
          last_name
        )
      `)
      .single();

    if (commentError) {
      logger.error('Error adding comment', commentError, {
        component: 'POST /api/campaign-uploads/[id]/comments',
        userId: currentUser.id,
      });
      return serverError('Failed to add comment');
    }

    return ok({
      data: {
        id: comment.id,
        text: comment.comment_text,
        type: comment.comment_type,
        date: comment.created_at,
        user: (comment as any).users
          ? `${(comment as any).users.first_name || ''} ${(comment as any).users.last_name || ''}`.trim() || (comment as any).users.email
          : 'Unknown User',
      },
    });
  } catch (error) {
    logger.error('Error in POST /api/campaign-uploads/[id]/comments', error, {
      component: 'POST /api/campaign-uploads/[id]/comments',
    });
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}

