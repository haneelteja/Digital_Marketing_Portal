import { NextRequest } from 'next/server';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError, notFound } from '../../../../../lib/apiResponse';
import { logger } from '../../../../../utils/logger';

// PUT /api/artwork-uploads/[id] - Update artwork upload (e.g., approval status)
export async function PUT(
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
    const { approved, comment } = body;

    // Fetch the upload
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

    const canApprove = 
      userData?.role === 'IT_ADMIN' ||
      userData?.role === 'AGENCY_ADMIN' ||
      (userData?.role === 'CLIENT' && userData.assigned_clients?.includes(artwork.campaign_client)) ||
      artwork.created_by === currentUser.id;

    if (!canApprove) {
      return unauthorized('You do not have permission to approve this upload');
    }

    // Update approval status
    const updateData: any = {
      updated_at: new Date().toISOString()
    };

    if (typeof approved === 'boolean') {
      updateData.approved = approved;
    }

    const { data: updatedUpload, error: updateError } = await supabaseAdmin
      .from('artwork_uploads')
      .update(updateData)
      .eq('id', uploadId)
      .select()
      .single();

    if (updateError) {
      logger.error('Error updating upload:', updateError);
      return serverError('Failed to update upload');
    }

    // Add comment if provided
    if (comment && comment.trim()) {
      const commentType = approved === true ? 'approval' : approved === false ? 'disapproval' : 'feedback';
      
      const { error: commentError } = await supabaseAdmin
        .from('artwork_upload_comments')
        .insert({
          artwork_upload_id: uploadId,
          user_id: currentUser.id,
          comment_text: comment.trim(),
          comment_type: commentType
        });

      if (commentError) {
        logger.error('Error adding comment:', commentError);
        // Don't fail the request if comment fails
      }
    }

    return ok({ data: updatedUpload });
  } catch (error) {
    logger.error('Error in PUT /api/artwork-uploads/[id]:', error);
    return serverError('Internal server error');
  }
}

