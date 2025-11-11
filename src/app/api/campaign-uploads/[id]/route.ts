import { NextRequest } from 'next/server';
import { supabase } from '../../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError, notFound } from '../../../../../lib/apiResponse';
import { logger } from '../../../../utils/logger';

// PUT /api/campaign-uploads/[id] - Update upload (approve/disapprove, add comment)
export async function PUT(
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
    const { approved, comment } = body;

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

    // Check access permissions - only IT_ADMIN, AGENCY_ADMIN, and CLIENT can approve
    const isAdmin = userRole === 'IT_ADMIN' || userRole === 'AGENCY_ADMIN';
    const isClient = userRole === 'CLIENT';
    const hasClientAccess = campaign.client_id && (
      assignedClients.includes(campaign.client_id) ||
      assignedClients.some(clientId => clientId === campaign.client_id)
    );

    if (approved !== undefined) {
      // Approval/disapproval requires admin or client access
      if (!isAdmin && !(isClient && hasClientAccess)) {
        return unauthorized('Only IT Admin, Agency Admin, or assigned Clients can approve uploads');
      }

      // If approving, require a comment
      if (approved === true && (!comment || !comment.trim())) {
        return badRequest('Approval comment is required');
      }

      // Update approval status
      const { error: updateError } = await supabaseAdmin
        .from('campaign_uploads')
        .update({
          approved,
          updated_at: new Date().toISOString(),
        })
        .eq('id', id);

      if (updateError) {
        logger.error('Error updating upload approval', updateError, {
          component: 'PUT /api/campaign-uploads/[id]',
          userId: currentUser.id,
          uploadId: id,
        });
        return serverError('Failed to update approval status');
      }

      // Add approval/disapproval comment if provided
      if (comment && comment.trim()) {
        const commentType = approved ? 'approval' : 'disapproval';
        const { error: commentError } = await supabaseAdmin
          .from('campaign_upload_comments')
          .insert([{
            campaign_upload_id: id,
            user_id: currentUser.id,
            comment_text: comment.trim(),
            comment_type: commentType,
          }]);

        if (commentError) {
          logger.error('Error adding approval comment', commentError, {
            component: 'PUT /api/campaign-uploads/[id]',
            userId: currentUser.id,
          });
          // Don't fail the request if comment fails
        }
      }
    }

    // Get updated upload with comments
    const { data: updatedUpload } = await supabaseAdmin
      .from('campaign_uploads')
      .select('*')
      .eq('id', id)
      .single();

    const { data: comments } = await supabaseAdmin
      .from('campaign_upload_comments')
      .select(`
        id,
        comment_text,
        comment_type,
        created_at,
        user_id,
        users:user_id (
          email,
          first_name,
          last_name
        )
      `)
      .eq('campaign_upload_id', id)
      .order('created_at', { ascending: false });

    return ok({
      data: {
        ...updatedUpload,
        comments: (comments || []).map((comment: any) => ({
          id: comment.id,
          text: comment.comment_text,
          type: comment.comment_type,
          date: comment.created_at,
          user: comment.users
            ? `${comment.users.first_name || ''} ${comment.users.last_name || ''}`.trim() || comment.users.email
            : 'Unknown User',
        })),
      },
    });
  } catch (error) {
    logger.error('Error in PUT /api/campaign-uploads/[id]', error, {
      component: 'PUT /api/campaign-uploads/[id]',
    });
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}


