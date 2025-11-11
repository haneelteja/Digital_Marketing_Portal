import { NextRequest } from 'next/server';
import { supabase } from '../../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';
import { ok, badRequest, unauthorized, serverError, notFound } from '../../../../../lib/apiResponse';

type UserRole = 'IT_ADMIN' | 'AGENCY_ADMIN' | 'CLIENT' | 'DESIGNER';

interface DbUser {
  role: UserRole;
  assigned_clients: string[] | string | null;
}

// PUT /api/calendar-entries/[id] - Update calendar entry (for DESIGNER to edit post content)
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
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return unauthorized('User not found');
    }

    // Get the existing entry
    const { data: existingEntry, error: entryError } = await supabaseAdmin
      .from('calendar_entries')
      .select('id, client, date')
      .eq('id', id)
      .single();

    if (entryError || !existingEntry) {
      return notFound('Calendar entry not found');
    }

    // Check access permissions
    const userRole = (userData as DbUser).role;
    const entryClient = (existingEntry as any).client;

    if (userRole === 'DESIGNER') {
      // DESIGNER can only edit entries for assigned clients
      const assignedClientsRaw = (userData as DbUser).assigned_clients;
      const assignedClients: string[] = Array.isArray(assignedClientsRaw)
        ? assignedClientsRaw.filter((id): id is string => typeof id === 'string')
        : (typeof assignedClientsRaw === 'string' 
            ? [assignedClientsRaw] 
            : []);

      if (assignedClients.length > 0 && !assignedClients.includes(entryClient)) {
        // Also check by client name for backward compatibility
        const { data: clientData } = await supabaseAdmin
          .from('clients')
          .select('id, company_name')
          .eq('id', entryClient)
          .single();

        const clientName = clientData?.company_name;
        if (!clientName || !assignedClients.some((id: string) => id === clientName)) {
          return unauthorized('You do not have access to edit this post');
        }
      }
    } else if (userRole === 'CLIENT') {
      // CLIENT cannot edit posts
      return unauthorized('Clients cannot edit posts');
    }
    // IT_ADMIN and AGENCY_ADMIN can edit any post

    const body = await request.json();

    // DESIGNER can only update specific fields (content-related fields)
    const allowedFields = [
      'post_content',
      'hashtags',
      'image_url',
      'content',
      'platform'
    ];

    // Filter body to only include allowed fields for DESIGNER
    let updateData: Record<string, any> = {};
    if (userRole === 'DESIGNER') {
      Object.keys(body).forEach(key => {
        if (allowedFields.includes(key)) {
          updateData[key] = body[key];
        }
      });
    } else {
      // IT_ADMIN and AGENCY_ADMIN can update all fields except core fields
      const restrictedFields = ['id', 'created_at', 'user_id'];
      Object.keys(body).forEach(key => {
        if (!restrictedFields.includes(key)) {
          updateData[key] = body[key];
        }
      });
    }

    if (Object.keys(updateData).length === 0) {
      return badRequest('No valid fields to update');
    }

    // Update the entry
    const { data: updatedEntry, error: updateError } = await supabaseAdmin
      .from('calendar_entries')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (updateError) {
      console.error('Database update error:', updateError);
      return serverError('Failed to update calendar entry');
    }

    return ok({ data: updatedEntry });
  } catch (error) {
    console.error('Error in PUT /api/calendar-entries/[id]:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}


