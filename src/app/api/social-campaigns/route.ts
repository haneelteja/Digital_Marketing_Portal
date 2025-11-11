import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { ok, created, badRequest, unauthorized, serverError, notFound } from '../../../../lib/apiResponse';
import { logger } from '../../../utils/logger';
import { Validator } from '../../../utils/validation';

type UserRole = 'IT_ADMIN' | 'AGENCY_ADMIN' | 'CLIENT' | 'DESIGNER';

interface DbUser {
  role: UserRole;
  assigned_clients: string[] | string | null;
}

interface SocialMediaCampaign {
  id: string;
  campaign_name: string;
  start_date: string;
  end_date: string;
  target_platforms: string[];
  budget: number | null;
  campaign_objective: string | null;
  assigned_users: string[];
  status: 'draft' | 'active' | 'completed' | 'cancelled';
  client_id: string | null;
  description: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

// GET /api/social-campaigns - Get all campaigns (filtered by user role)
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

    // Get user role and assigned clients
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return unauthorized('User not found');
    }

    const userRole = (userData as DbUser).role;
    let query = supabaseAdmin
      .from('social_media_campaigns')
      .select('*')
      .is('deleted_at', null)
      .order('created_at', { ascending: false });

    // Filter based on role
    if (userRole === 'CLIENT' || userRole === 'DESIGNER') {
      // CLIENT and DESIGNER can only see campaigns where they are assigned or for their assigned clients
      const assignedClientsRaw = (userData as DbUser).assigned_clients;
      const assignedClients: string[] = Array.isArray(assignedClientsRaw)
        ? assignedClientsRaw.filter((id): id is string => typeof id === 'string')
        : (typeof assignedClientsRaw === 'string'
            ? [assignedClientsRaw]
            : []);

      // Build OR conditions: user is assigned OR client_id is in assigned clients
      if (assignedClients.length > 0) {
        // User is assigned OR client_id matches one of assigned clients
        query = query.or(
          `assigned_users.cs.{${currentUser.id}},client_id.in.(${assignedClients.join(',')})`
        );
      } else {
        // If no assigned clients, only show campaigns where user is assigned
        query = query.contains('assigned_users', [currentUser.id]);
      }
    }
    // IT_ADMIN and AGENCY_ADMIN can see all campaigns (no additional filter needed)

    const { data: campaigns, error } = await query;

    if (error) {
      logger.error('Error fetching campaigns', error, {
        component: 'GET /api/social-campaigns',
        userId: currentUser.id,
        userRole: userRole,
      });
      return serverError('Failed to fetch campaigns');
    }

    logger.info('Campaigns fetched successfully', {
      component: 'GET /api/social-campaigns',
      userId: currentUser.id,
      count: campaigns?.length || 0,
    });

    return ok({ data: campaigns || [] });
  } catch (error) {
    logger.error('Error in GET /api/social-campaigns', error, {
      component: 'GET /api/social-campaigns',
    });
    const errorMessage = error instanceof Error ? error.message : String(error);
    // Don't expose internal error details in production
    const safeMessage = process.env.NODE_ENV === 'development' 
      ? `Internal server error: ${errorMessage}`
      : 'Internal server error';
    return serverError(safeMessage);
  }
}

// POST /api/social-campaigns - Create new campaign
export async function POST(request: NextRequest) {
  logger.info('POST /api/social-campaigns - Request received');
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

    // Only IT_ADMIN and AGENCY_ADMIN can create campaigns
    if (userRole !== 'IT_ADMIN' && userRole !== 'AGENCY_ADMIN') {
      return unauthorized('Only IT Admin and Agency Admin can create campaigns');
    }

    const body = await request.json();

    // Validate campaign data
    const validation = Validator.campaign(body);
    if (!validation.valid) {
      logger.warn('Campaign validation failed', {
        component: 'POST /api/social-campaigns',
        userId: currentUser.id,
        errors: validation.errors,
      });
      return badRequest('Validation failed', validation.errors);
    }

    // Additional validation (already done by Validator.campaign, but keep for safety)
    const startDate = new Date(body.start_date);
    const endDate = new Date(body.end_date);
    
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return badRequest('Invalid date format');
    }

    if (endDate < startDate) {
      return badRequest('End date must be after start date');
    }

    // Prepare campaign data with sanitization
    // Client ID is now mandatory - validate it exists
    const clientId = body.client_id && body.client_id.trim() !== '' ? body.client_id.trim() : null;
    if (!clientId) {
      return badRequest('Client is required');
    }
    
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
    
    // Budget is now mandatory
    if (!body.budget || body.budget === '' || body.budget === null) {
      return badRequest('Budget is required');
    }
    const budgetValue = parseFloat(String(body.budget));
    if (isNaN(budgetValue) || budgetValue < 0) {
      return badRequest('Budget must be a valid positive number');
    }
    
    const campaignData = {
      campaign_name: Validator.sanitizeString(body.campaign_name, 255),
      start_date: body.start_date,
      end_date: body.end_date,
      target_platforms: Array.isArray(body.target_platforms) ? body.target_platforms : [],
      budget: budgetValue,
      campaign_objective: body.campaign_objective && body.campaign_objective.trim() !== '' ? Validator.sanitizeString(body.campaign_objective, 100) : null,
      assigned_users: Array.isArray(body.assigned_users) ? body.assigned_users : [],
      status: body.status || 'draft',
      client_id: clientId,
      description: body.description && body.description.trim() !== '' ? Validator.sanitizeString(body.description, 5000) : null,
      created_by: currentUser.id,
    };

    // Log campaign data before insert (for debugging)
    logger.info('Attempting to create campaign', {
      component: 'POST /api/social-campaigns',
      userId: currentUser.id,
      campaignData: {
        ...campaignData,
        assigned_users: campaignData.assigned_users.length,
      },
    });

    // Insert campaign
    const { data: campaign, error: insertError } = await supabaseAdmin
      .from('social_media_campaigns')
      .insert(campaignData)
      .select()
      .single();

    if (insertError) {
      logger.error('Error creating campaign', insertError, {
        component: 'POST /api/social-campaigns',
        userId: currentUser.id,
        campaignData: {
          ...campaignData,
          assigned_users: campaignData.assigned_users.length,
        },
        errorCode: (insertError as any)?.code,
        errorMessage: insertError.message,
        errorDetails: insertError.details,
      });
      
      // Provide more specific error message
      const errorMessage = insertError.message || 'Failed to create campaign';
      if (errorMessage.includes('foreign key') || errorMessage.includes('client_id')) {
        return badRequest('Invalid client ID. Please select a valid client.');
      }
      if (errorMessage.includes('violates check constraint')) {
        return badRequest('Invalid data format. Please check all fields and try again.');
      }
      
      return serverError(`Failed to create campaign: ${errorMessage}`);
    }

    logger.info('Campaign created successfully', {
      component: 'POST /api/social-campaigns',
      userId: currentUser.id,
      campaignId: campaign.id,
    });

    return created({ data: campaign });
  } catch (error) {
    logger.error('Error in POST /api/social-campaigns', error, {
      component: 'POST /api/social-campaigns',
    });
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}

