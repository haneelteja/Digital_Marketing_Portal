import { NextRequest } from 'next/server';
import { supabase } from '../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError, notFound } from '../../../../lib/apiResponse';
import { logger } from '../../../utils/logger';

// GET /api/campaign-uploads - Get uploads for a campaign
export async function GET(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    const { searchParams } = new URL(request.url);
    const campaignId = searchParams.get('campaignId');

    if (!campaignId) {
      return badRequest('campaignId is required');
    }

    // Verify campaign exists and user has access
    const { data: campaign, error: campaignError } = await supabaseAdmin
      .from('social_media_campaigns')
      .select('id, client_id, assigned_users, created_by')
      .eq('id', campaignId)
      .is('deleted_at', null)
      .single();

    if (campaignError || !campaign) {
      return notFound('Campaign not found');
    }

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
      assignedClients.some(id => id === campaign.client_id)
    );

    if (!isAdmin && !isCreator && !isAssigned && !hasClientAccess) {
      return unauthorized('You do not have access to this campaign');
    }

    // Get uploads for the campaign
    const { data: uploads, error: uploadsError } = await supabaseAdmin
      .from('campaign_uploads')
      .select('*')
      .eq('campaign_id', campaignId)
      .order('option_number', { ascending: true });

    if (uploadsError) {
      logger.error('Error fetching campaign uploads', uploadsError, {
        component: 'GET /api/campaign-uploads',
        userId: currentUser.id,
        campaignId,
      });
      return serverError('Failed to fetch uploads');
    }

    // Get comments for each upload
    const uploadsWithComments = await Promise.all(
      (uploads || []).map(async (upload) => {
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
          .eq('campaign_upload_id', upload.id)
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
  } catch (error) {
    logger.error('Error in GET /api/campaign-uploads', error, {
      component: 'GET /api/campaign-uploads',
    });
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}

// POST /api/campaign-uploads - Upload a file for a campaign
export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    const formData = await request.formData();
    const file = formData.get('file') as File;
    const campaignId = formData.get('campaignId') as string;
    const optionNumber = parseInt(formData.get('optionNumber') as string);
    const description = formData.get('description') as string | null;

    if (!file || !campaignId || !optionNumber || (optionNumber < 1 || optionNumber > 2)) {
      return badRequest('Missing required fields: file, campaignId, optionNumber (1-2)');
    }

    // Verify campaign exists and user has access
    const { data: campaign, error: campaignError } = await supabaseAdmin
      .from('social_media_campaigns')
      .select('id, client_id, assigned_users, created_by')
      .eq('id', campaignId)
      .is('deleted_at', null)
      .single();

    if (campaignError || !campaign) {
      return notFound('Campaign not found');
    }

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
      assignedClients.some(id => id === campaign.client_id)
    );

    if (!isAdmin && !isCreator && !isAssigned && !hasClientAccess) {
      return unauthorized('You do not have access to upload to this campaign');
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
    const fileName = `${campaignId}/${optionNumber}_${timestamp}_${sanitizedFileName}`;
    const filePath = `campaign-uploads/${fileName}`;

    // Convert File to ArrayBuffer
    const arrayBuffer = await file.arrayBuffer();
    const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
      .from('campaign-media')
      .upload(filePath, arrayBuffer, {
        contentType: file.type,
        upsert: false,
      });

    if (uploadError) {
      logger.error('Storage upload error', uploadError, {
        component: 'POST /api/campaign-uploads',
        userId: currentUser.id,
        campaignId,
      });
      return serverError('Failed to upload file to storage');
    }

    // Get public URL for the uploaded file
    const { data: urlData } = supabaseAdmin.storage
      .from('campaign-media')
      .getPublicUrl(filePath);

    const fileUrl = urlData.publicUrl;

    // Check if upload already exists for this option (upsert)
    const { data: existingUpload } = await supabaseAdmin
      .from('campaign_uploads')
      .select('id, file_url')
      .eq('campaign_id', campaignId)
      .eq('option_number', optionNumber)
      .single();

    let uploadRecord;
    if (existingUpload) {
      // Delete old file from storage
      try {
        const oldFilePath = existingUpload.file_url.split('/').slice(-2).join('/');
        await supabaseAdmin.storage.from('campaign-media').remove([`campaign-uploads/${oldFilePath}`]);
      } catch (e) {
        logger.warn('Failed to delete old file', e, {
          component: 'POST /api/campaign-uploads',
        });
      }

      // Update existing upload
      const { data: updated, error: updateError } = await supabaseAdmin
        .from('campaign_uploads')
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
        logger.error('Database update error', updateError, {
          component: 'POST /api/campaign-uploads',
          userId: currentUser.id,
        });
        // Try to clean up uploaded file
        await supabaseAdmin.storage.from('campaign-media').remove([filePath]);
        return serverError('Failed to update upload metadata');
      }

      uploadRecord = updated;
    } else {
      // Insert new upload
      const { data: inserted, error: insertError } = await supabaseAdmin
        .from('campaign_uploads')
        .insert([{
          campaign_id: campaignId,
          option_number: optionNumber,
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
        logger.error('Database insert error', insertError, {
          component: 'POST /api/campaign-uploads',
          userId: currentUser.id,
        });
        // Try to clean up uploaded file
        await supabaseAdmin.storage.from('campaign-media').remove([filePath]);
        return serverError('Failed to save upload metadata');
      }

      uploadRecord = inserted;
    }

    logger.info('Campaign upload created/updated successfully', {
      component: 'POST /api/campaign-uploads',
      userId: currentUser.id,
      campaignId,
      optionNumber,
      uploadId: uploadRecord.id,
    });

    return ok({
      data: {
        id: uploadRecord.id,
        fileUrl,
        fileName: file.name,
        fileType: file.type,
        fileSize: file.size,
        description,
        approved: uploadRecord.approved,
        optionNumber,
      },
    });
  } catch (error) {
    logger.error('Error in POST /api/campaign-uploads', error, {
      component: 'POST /api/campaign-uploads',
    });
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}

