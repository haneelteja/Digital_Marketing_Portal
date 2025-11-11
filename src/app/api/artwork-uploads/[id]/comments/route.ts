import { NextRequest } from 'next/server';
import { supabaseAdmin } from '../../../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError, notFound } from '../../../../../../lib/apiResponse';
import { logger } from '../../../../../../utils/logger';

// POST /api/artwork-uploads/[id]/comments - Add a comment to an artwork upload
export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabaseAdmin.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    const uploadId = params.id;
    const body = await request.json();
    const { commentText, commentType = 'feedback' } = body;

    if (!commentText || !commentText.trim()) {
      return badRequest('commentText is required');
    }

    // Verify the upload exists and user has access
    const { data: upload, error: uploadError } = await supabaseAdmin
      .from('artwork_uploads')
      .select('*, artworks(*)')
      .eq('id', uploadId)
      .single();

    if (uploadError || !upload) {
      return notFound('Upload not found');
    }

    const artwork = upload.artworks;

    // Check user role and access
    const { data: userData } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    const canComment = 
      userData?.role === 'IT_ADMIN' ||
      userData?.role === 'AGENCY_ADMIN' ||
      userData?.role === 'CLIENT' ||
      artwork.created_by === currentUser.id ||
      artwork.designer_owner === currentUser.id ||
      (userData?.role === 'DESIGNER' && (
        artwork.designer_owner === currentUser.id ||
        userData.assigned_clients?.includes(artwork.campaign_client)
      ));

    if (!canComment) {
      return unauthorized('You do not have permission to comment on this upload');
    }

    // Insert comment
    const { data: comment, error: commentError } = await supabaseAdmin
      .from('artwork_upload_comments')
      .insert({
        artwork_upload_id: uploadId,
        user_id: currentUser.id,
        comment_text: commentText.trim(),
        comment_type: commentType
      })
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
      .single();

    if (commentError) {
      logger.error('Error adding comment:', commentError);
      return serverError('Failed to add comment');
    }

    // Format comment response
    const commentWithUser = {
      id: comment.id,
      text: comment.comment_text,
      type: comment.comment_type,
      date: comment.created_at,
      user: comment.users
        ? `${comment.users.first_name || ''} ${comment.users.last_name || ''}`.trim() || comment.users.email
        : 'Unknown User',
    };

    return ok({ data: commentWithUser });
  } catch (error) {
    logger.error('Error in POST /api/artwork-uploads/[id]/comments:', error);
    return serverError('Internal server error');
  }
}

