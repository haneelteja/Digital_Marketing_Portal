import { NextRequest } from 'next/server';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError, notFound } from '../../../../lib/apiResponse';
import { logger } from '../../../utils/logger';

// GET /api/artwork-uploads - Get uploads for an artwork
export async function GET(request: NextRequest) {
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

    const { searchParams } = new URL(request.url);
    const artworkId = searchParams.get('artworkId');

    if (!artworkId) {
      return badRequest('artworkId is required');
    }

    // Verify user has access to this artwork
    const { data: artwork, error: artworkError } = await supabaseAdmin
      .from('artworks')
      .select('id, campaign_client, designer_owner, created_by, deleted_at')
      .eq('id', artworkId)
      .single();

    if (artworkError || !artwork || artwork.deleted_at) {
      return notFound('Artwork not found');
    }

    // Check user role and access
    const { data: userData } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    const hasAccess = 
      userData?.role === 'IT_ADMIN' ||
      userData?.role === 'AGENCY_ADMIN' ||
      artwork.created_by === currentUser.id ||
      artwork.designer_owner === currentUser.id ||
      (userData?.role === 'CLIENT' && userData.assigned_clients?.includes(artwork.campaign_client)) ||
      (userData?.role === 'DESIGNER' && (
        artwork.designer_owner === currentUser.id ||
        userData.assigned_clients?.includes(artwork.campaign_client)
      ));

    if (!hasAccess) {
      return unauthorized('You do not have access to this artwork');
    }

    // Fetch uploads
    const { data: uploads, error: uploadsError } = await supabaseAdmin
      .from('artwork_uploads')
      .select('*')
      .eq('artwork_id', artworkId)
      .order('option_number', { ascending: true });

    if (uploadsError) {
      logger.error('Error fetching artwork uploads:', uploadsError);
      return serverError('Failed to fetch uploads');
    }

    // Fetch comments for each upload with user information
    if (uploads && uploads.length > 0) {
      const uploadsWithComments = await Promise.all(
        uploads.map(async (upload) => {
          const { data: comments } = await supabaseAdmin
            .from('artwork_upload_comments')
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
            .eq('artwork_upload_id', upload.id)
            .order('created_at', { ascending: false });

          return {
            ...upload,
            comments: (comments || []).map((comment: any) => ({
              id: comment.id,
              text: comment.comment_text,
              type: comment.comment_type,
              date: comment.created_at,
              user: comment.users
                ? `${comment.users.first_name || ''} ${comment.users.last_name || ''}`.trim() || comment.users.email
                : 'Unknown User',
            })),
          };
        })
      );

      return ok({ data: uploadsWithComments });
    }

    return ok({ data: uploads || [] });
  } catch (error) {
    logger.error('Error in GET /api/artwork-uploads:', error);
    return serverError('Internal server error');
  }
}

// POST /api/artwork-uploads - Upload a file for an artwork
export async function POST(request: NextRequest) {
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

    const formData = await request.formData();
    const artworkId = formData.get('artworkId') as string;
    const optionNumber = formData.get('optionNumber') as string;
    const file = formData.get('file') as File;
    const description = formData.get('description') as string | null;

    if (!artworkId || !optionNumber || !file) {
      return badRequest('artworkId, optionNumber, and file are required');
    }

    const optionNum = parseInt(optionNumber, 10);
    if (optionNum !== 1 && optionNum !== 2) {
      return badRequest('optionNumber must be 1 or 2');
    }

    // Verify user has access to this artwork
    const { data: artwork, error: artworkError } = await supabaseAdmin
      .from('artworks')
      .select('id, campaign_client, designer_owner, created_by, deleted_at')
      .eq('id', artworkId)
      .single();

    if (artworkError || !artwork || artwork.deleted_at) {
      return notFound('Artwork not found');
    }

    // Check user role and access
    const { data: userData } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    const canUpload = 
      userData?.role === 'IT_ADMIN' ||
      userData?.role === 'AGENCY_ADMIN' ||
      artwork.created_by === currentUser.id ||
      artwork.designer_owner === currentUser.id ||
      (userData?.role === 'DESIGNER' && (
        artwork.designer_owner === currentUser.id ||
        userData.assigned_clients?.includes(artwork.campaign_client)
      ));

    if (!canUpload) {
      return unauthorized('You do not have permission to upload files for this artwork');
    }

    // Validate file type
    const isImage = file.type.startsWith('image/');
    const isVideo = file.type.startsWith('video/');
    if (!isImage && !isVideo) {
      return badRequest('File must be an image or video');
    }

    // Upload file to Supabase Storage
    const fileExt = file.name.split('.').pop() || 'bin';
    const sanitizedFileName = file.name.replace(/[^a-zA-Z0-9.-]/g, '_');
    const timestamp = Date.now();
    const fileName = `${artworkId}/${optionNum}_${timestamp}_${sanitizedFileName}`;
    const filePath = `artwork-uploads/${fileName}`;

    // Convert File to ArrayBuffer
    const arrayBuffer = await file.arrayBuffer();
    const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
      .from('artwork-media')
      .upload(filePath, arrayBuffer, {
        contentType: file.type,
        upsert: false
      });

    if (uploadError) {
      logger.error('Error uploading file to storage:', uploadError);
      return serverError('Failed to upload file to storage');
    }

    // Get public URL
    const { data: urlData } = supabaseAdmin.storage
      .from('artwork-media')
      .getPublicUrl(filePath);

    const fileUrl = urlData.publicUrl;

    // Check if upload already exists for this option (upsert)
    const { data: existingUpload } = await supabaseAdmin
      .from('artwork_uploads')
      .select('id, file_url')
      .eq('artwork_id', artworkId)
      .eq('option_number', optionNum)
      .single();

    let uploadRecord;
    if (existingUpload) {
      // Delete old file from storage
      try {
        const oldFilePath = existingUpload.file_url.split('/').slice(-2).join('/');
        await supabaseAdmin.storage.from('artwork-media').remove([`artwork-uploads/${oldFilePath}`]);
      } catch (e) {
        logger.warn('Failed to delete old file', e);
      }

      // Update existing upload
      const { data: updated, error: updateError } = await supabaseAdmin
        .from('artwork_uploads')
        .update({
          file_url: fileUrl,
          file_name: file.name,
          file_type: file.type,
          file_size: file.size,
          description: description || null,
          approved: false, // Reset approval when new file is uploaded
          updated_at: new Date().toISOString(),
        })
        .eq('id', existingUpload.id)
        .select()
        .single();

      if (updateError) {
        logger.error('Database update error', updateError);
        await supabaseAdmin.storage.from('artwork-media').remove([filePath]);
        return serverError('Failed to update upload metadata');
      }

      uploadRecord = updated;
    } else {
      // Insert new upload
      const { data: inserted, error: insertError } = await supabaseAdmin
        .from('artwork_uploads')
        .insert([{
          artwork_id: artworkId,
          option_number: optionNum,
          file_url: fileUrl,
          file_name: file.name,
          file_type: file.type,
          file_size: file.size,
          description: description || null,
          approved: false,
          uploaded_by: currentUser.id,
        }])
        .select()
        .single();

      if (insertError) {
        logger.error('Database insert error', insertError);
        await supabaseAdmin.storage.from('artwork-media').remove([filePath]);
        return serverError('Failed to save upload metadata');
      }

      uploadRecord = inserted;
    }

    return ok({ data: uploadRecord });
  } catch (error) {
    logger.error('Error in POST /api/artwork-uploads:', error);
    return serverError('Internal server error');
  }
}

