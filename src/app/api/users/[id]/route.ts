import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '../../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';
import { UpdateUserRequest } from '../../../../types/user';

// GET /api/users/[id] - Get specific user
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    // Get current user's role using admin client to bypass RLS
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients, client_id')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Check permissions
    if (userData.role === 'CLIENT' && id !== currentUser.id) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    if (userData.role === 'AGENCY_ADMIN') {
      // Check if user is associated with agency admin's clients
      const { data: targetUser, error: targetError } = await supabaseAdmin
        .from('users')
        .select('client_id')
        .eq('id', id)
        .single();

      if (targetError || !targetUser) {
        return NextResponse.json({ error: 'User not found' }, { status: 404 });
      }

      if (targetUser.client_id && userData.assigned_clients && 
          !userData.assigned_clients.includes(targetUser.client_id) && 
          id !== currentUser.id) {
        return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
      }
    }

    // Get user using admin client to bypass RLS
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('id', id)
      .single();

    if (error) {
      console.error('Error fetching user:', error);
      return NextResponse.json({ error: 'Failed to fetch user' }, { status: 500 });
    }

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    return NextResponse.json(user);
  } catch (error) {
    console.error('Error in GET /api/users/[id]:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// PUT /api/users/[id] - Update user
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    // Get current user's role using admin client to bypass RLS
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients, client_id')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Check permissions
    const canEdit = userData.role === 'IT_ADMIN' || id === currentUser.id;
    if (!canEdit) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    const body: UpdateUserRequest = await request.json();

    // Validate role-specific fields
    if (body.role === 'AGENCY_ADMIN' && (!body.assignedClients || body.assignedClients.length === 0)) {
      return NextResponse.json({ error: 'Agency admins must be assigned to at least one client' }, { status: 400 });
    }

    if (body.role === 'CLIENT' && (!body.assignedClients || body.assignedClients.length === 0)) {
      return NextResponse.json({ error: 'Client users must be assigned to at least one client' }, { status: 400 });
    }

    // Prepare update data
    const updateData: any = {
      updated_at: new Date().toISOString()
    };

    if (body.firstName !== undefined) updateData.first_name = body.firstName;
    if (body.lastName !== undefined) updateData.last_name = body.lastName;
    if (body.role !== undefined && userData.role === 'IT_ADMIN') updateData.role = body.role;
    if (body.isActive !== undefined && userData.role === 'IT_ADMIN') updateData.is_active = body.isActive;
    if (body.assignedClients !== undefined && userData.role === 'IT_ADMIN') updateData.assigned_clients = body.assignedClients;
    if (body.clientId !== undefined && userData.role === 'IT_ADMIN') updateData.client_id = body.clientId;

    // Update user using admin client to bypass RLS
    const { data: updatedUser, error } = await supabaseAdmin
      .from('users')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) {
      console.error('Error updating user:', error);
      return NextResponse.json({ error: 'Failed to update user', details: error.message }, { status: 500 });
    }

    if (!updatedUser) {
      return NextResponse.json({ error: 'User not found after update' }, { status: 404 });
    }

    // Log activity
    await logActivity(currentUser.id, 'UPDATE_USER', id, body);

    // Map database response to frontend format (camelCase)
    const mappedUser = {
      id: updatedUser.id,
      email: updatedUser.email,
      firstName: updatedUser.first_name,
      lastName: updatedUser.last_name,
      role: updatedUser.role,
      isActive: updatedUser.is_active,
      emailVerified: updatedUser.email_verified,
      assignedClients: updatedUser.assigned_clients || undefined,
      clientId: updatedUser.client_id || undefined,
      lastLoginAt: updatedUser.last_login_at || undefined,
      createdAt: updatedUser.created_at,
      updatedAt: updatedUser.updated_at
    };

    return NextResponse.json(mappedUser);
  } catch (error) {
    console.error('Error in PUT /api/users/[id]:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// DELETE /api/users/[id] - Delete user
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    // Get current user's role using admin client to bypass RLS
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData || userData.role !== 'IT_ADMIN') {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Prevent self-deletion
    if (id === currentUser.id) {
      return NextResponse.json({ error: 'Cannot delete your own account' }, { status: 400 });
    }

    // Get user before deletion for logging using admin client to bypass RLS
    const { data: userToDelete, error: fetchError } = await supabaseAdmin
      .from('users')
      .select('email, first_name, last_name')
      .eq('id', id)
      .single();

    if (fetchError) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Delete from database using admin client to bypass RLS
    const { error: dbError } = await supabaseAdmin
      .from('users')
      .delete()
      .eq('id', id);

    if (dbError) {
      console.error('Error deleting user from database:', dbError);
      return NextResponse.json({ error: 'Failed to delete user' }, { status: 500 });
    }

    // Delete from auth (this should be done carefully in production)
    const { error: deleteAuthError } = await supabaseAdmin.auth.admin.deleteUser(id);
    if (deleteAuthError) {
      console.error('Error deleting user from auth:', deleteAuthError);
      // Don't fail the request if auth deletion fails, as the database record is already deleted
    }

    // Log activity using stored user info instead of deleted user ID to avoid foreign key constraint
    await logActivity(currentUser.id, 'DELETE_USER', null, {
      email: userToDelete.email,
      firstName: userToDelete.first_name,
      lastName: userToDelete.last_name,
      deletedUserId: id
    });

    return NextResponse.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error in DELETE /api/users/[id]:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// Helper function to log activities using admin client to bypass RLS
async function logActivity(userId: string, action: string, targetUserId: string | null, details: any) {
  try {
    await supabaseAdmin.from('activity_logs').insert([{
      user_id: userId,
      action,
      target_user_id: targetUserId,
      details,
      timestamp: new Date().toISOString(),
      ip_address: '127.0.0.1',
      user_agent: 'Digital Marketing Portal'
    }]);
  } catch (error) {
    console.error('Failed to log activity:', error);
  }
}
