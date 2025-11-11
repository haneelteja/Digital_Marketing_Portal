import { NextRequest } from 'next/server';
import { supabase } from '../../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError, notFound } from '../../../../../lib/apiResponse';

type UserRole = 'IT_ADMIN' | 'AGENCY_ADMIN' | 'CLIENT' | 'DESIGNER';

interface DbUser {
  role: UserRole;
}

// PUT /api/social-campaigns/[id] - Update campaign
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

    // Get user role
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return unauthorized('User not found');
    }

    // Get existing campaign
    const { data: existingCampaign, error: campaignError } = await supabaseAdmin
      .from('social_media_campaigns')
      .select('*')
      .eq('id', id)
      .is('deleted_at', null)
      .single();

    if (campaignError || !existingCampaign) {
      return notFound('Campaign not found');
    }

    const userRole = (userData as DbUser).role;

    // Check permissions: user must be creator, assigned, or IT_ADMIN/AGENCY_ADMIN
    const isCreator = existingCampaign.created_by === currentUser.id;
    const isAssigned = Array.isArray(existingCampaign.assigned_users) && 
                      existingCampaign.assigned_users.includes(currentUser.id);
    const isAdmin = userRole === 'IT_ADMIN' || userRole === 'AGENCY_ADMIN';

    if (!isCreator && !isAssigned && !isAdmin) {
      return unauthorized('You do not have permission to update this campaign');
    }

    const body = await request.json();

    // Validate dates if provided
    if (body.start_date || body.end_date) {
      const startDate = body.start_date ? new Date(body.start_date) : new Date(existingCampaign.start_date);
      const endDate = body.end_date ? new Date(body.end_date) : new Date(existingCampaign.end_date);
      
      if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
        return badRequest('Invalid date format');
      }

      if (endDate < startDate) {
        return badRequest('End date must be after start date');
      }
    }

    // Validate target_platforms if provided (now optional, so just ensure it's an array)
    if (body.target_platforms !== undefined && !Array.isArray(body.target_platforms)) {
      return badRequest('Target platforms must be an array');
    }

    // Validate status if provided
    if (body.status) {
      const validStatuses = ['draft', 'active', 'completed', 'cancelled'];
      if (!validStatuses.includes(body.status)) {
        return badRequest(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
      }
    }

    // Prepare update data
    const updateData: Record<string, any> = {};
    
    if (body.campaign_name !== undefined) updateData.campaign_name = body.campaign_name.trim();
    if (body.start_date !== undefined) updateData.start_date = body.start_date;
    if (body.end_date !== undefined) updateData.end_date = body.end_date;
    if (body.target_platforms !== undefined) updateData.target_platforms = Array.isArray(body.target_platforms) ? body.target_platforms : [];
    
    // Budget is now mandatory - validate if provided
    if (body.budget !== undefined) {
      if (body.budget === '' || body.budget === null) {
        return badRequest('Budget is required');
      }
      const budgetValue = parseFloat(String(body.budget));
      if (isNaN(budgetValue) || budgetValue < 0) {
        return badRequest('Budget must be a valid positive number');
      }
      updateData.budget = budgetValue;
    }
    
    if (body.campaign_objective !== undefined) updateData.campaign_objective = body.campaign_objective && body.campaign_objective.trim() !== '' ? body.campaign_objective.trim() : null;
    if (body.assigned_users !== undefined) updateData.assigned_users = Array.isArray(body.assigned_users) ? body.assigned_users : [];
    if (body.status !== undefined) updateData.status = body.status || 'draft';
    
    // Client ID is now mandatory - validate if provided
    if (body.client_id !== undefined) {
      if (!body.client_id || body.client_id.trim() === '') {
        return badRequest('Client is required');
      }
      const clientId = body.client_id.trim();
      
      // Verify client exists and is not deleted
      const { data: clientData, error: clientError } = await supabaseAdmin
        .from('clients')
        .select('id')
        .eq('id', clientId)
        .is('deleted_at', null)
        .single();
      
      if (clientError || !clientData) {
        return badRequest('Invalid client. Please select a valid client.');
      }
      
      updateData.client_id = clientId;
    }
    
    if (body.description !== undefined) updateData.description = body.description && body.description.trim() !== '' ? body.description.trim() : null;

    // Update campaign
    const { data: updatedCampaign, error: updateError } = await supabaseAdmin
      .from('social_media_campaigns')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (updateError) {
      console.error('Error updating campaign:', updateError);
      return serverError('Failed to update campaign');
    }

    return ok({ data: updatedCampaign });
  } catch (error) {
    console.error('Error in PUT /api/social-campaigns/[id]:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}

// DELETE /api/social-campaigns/[id] - Soft delete campaign
export async function DELETE(
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

    // Get user role
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return unauthorized('User not found');
    }

    const userRole = (userData as DbUser).role;

    // Only IT_ADMIN and AGENCY_ADMIN can delete campaigns
    if (userRole !== 'IT_ADMIN' && userRole !== 'AGENCY_ADMIN') {
      return unauthorized('Only IT Admin and Agency Admin can delete campaigns');
    }

    // Soft delete by setting deleted_at
    const { error: deleteError } = await supabaseAdmin
      .from('social_media_campaigns')
      .update({ deleted_at: new Date().toISOString() })
      .eq('id', id);

    if (deleteError) {
      console.error('Error deleting campaign:', deleteError);
      return serverError('Failed to delete campaign');
    }

    return ok({ message: 'Campaign deleted successfully' });
  } catch (error) {
    console.error('Error in DELETE /api/social-campaigns/[id]:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}



