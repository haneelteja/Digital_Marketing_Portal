import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { User, CreateUserRequest, UserRole } from '../../../types/user';
import { sendWelcomeEmail, sendEmailFailureAlert } from '../../../../lib/email';
import { ok, created, badRequest, unauthorized, forbidden, notFound, serverError } from '../../../../lib/apiResponse';
import { isEmail, isStringArray, isNonEmptyString } from '../../../../lib/validate';

// Database row shape for users table
type DbUserRow = {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: UserRole;
  is_active: boolean;
  email_verified: boolean;
  assigned_clients: string[] | null;
  client_id: string | null;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
};

// GET /api/users - Get all users (with RBAC filtering)
export async function GET(request: NextRequest) {
  try {
    // Get current user from auth header
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    
    // Verify token and get current user
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    // Get user role from database using admin client to bypass RLS
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients, client_id')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      console.error('User not found in database:', userError);
      return notFound('User not found in database. Please ensure you have a user record.');
    }

    // Apply RBAC filtering using admin client to bypass RLS
    let query = supabaseAdmin.from('users').select('*');
    
    if (userData.role === 'AGENCY_ADMIN') {
      // Agency admins can only see users associated with their assigned clients
      if (userData.assigned_clients && userData.assigned_clients.length > 0) {
        // Use .in() for better performance with indexes
        // First get users with matching client_id, then add self
        const clientIds = userData.assigned_clients.filter((id: string | null | undefined): id is string => typeof id === 'string' && id.trim().length > 0);
        if (clientIds.length > 0) {
          query = query.or(`client_id.in.(${clientIds.join(',')}),id.eq.${currentUser.id}`);
        } else {
          query = query.eq('id', currentUser.id);
        }
      } else {
        query = query.eq('id', currentUser.id);
      }
    } else if (userData.role === 'CLIENT') {
      // Clients can only see themselves
      query = query.eq('id', currentUser.id);
    }
    // IT_ADMIN can see all users (no additional filtering)

    // Execute query with timeout protection
    const queryPromise = query.order('created_at', { ascending: false });
    
    let users: DbUserRow[] | null = null;
    let error: any = null;
    
    try {
      // Race the query against a timeout
      const result = await Promise.race([
        queryPromise,
        new Promise<{ data: null, error: { message: 'Query timeout' } }>((_, reject) => 
          setTimeout(() => reject(new Error('Query timeout after 20 seconds')), 20000)
        )
      ]);
      users = (result as { data: DbUserRow[] | null, error: any }).data;
      error = (result as { data: DbUserRow[] | null, error: any }).error;
    } catch (timeoutError) {
      if (timeoutError instanceof Error && timeoutError.message.includes('timeout')) {
        console.error('User query timed out');
        return serverError('Query timeout. Please try again.');
      }
      throw timeoutError;
    }

    if (error) {
      console.error('Error fetching users:', error);
      return serverError('Failed to fetch users');
    }

    // Map database column names to frontend property names

    const mappedUsers = (users as DbUserRow[] | null || []).map((user) => ({
      id: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      isActive: user.is_active,
      emailVerified: user.email_verified,
      assignedClients: user.assigned_clients,
      clientId: user.client_id,
      lastLoginAt: user.last_login_at,
      createdAt: user.created_at,
      updatedAt: user.updated_at
    }));

    return ok({ users: mappedUsers });
  } catch (error) {
    console.error('Error in GET /api/users:', error);
    return serverError();
  }
}

// POST /api/users - Create new user
export async function POST(request: NextRequest) {
  try {
    // Get current user from auth header
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    
    // Verify token and get current user
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    // Check if current user can create users using admin client to bypass RLS
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData || userData.role !== 'IT_ADMIN') {
      return forbidden('Insufficient permissions');
    }

    const body = (await request.json()) as CreateUserRequest;
    
    // Validate required fields
    if (!isEmail(body.email) || !isNonEmptyString(body.firstName) || !isNonEmptyString(body.lastName) || !isNonEmptyString(body.role)) {
      return badRequest('Missing or invalid required fields');
    }

    // Validate role-specific fields
    if (body.role === 'AGENCY_ADMIN' && (!isStringArray(body.assignedClients) || body.assignedClients.length === 0)) {
      return badRequest('Agency admins must be assigned to at least one client');
    }

    if (body.role === 'CLIENT' && (!isStringArray(body.assignedClients) || body.assignedClients.length === 0)) {
      return badRequest('Client users must be assigned to at least one client');
    }

    // Check if user already exists using admin client to bypass RLS
    const { data: existingUser, error: checkError } = await supabaseAdmin
      .from('users')
      .select('id')
      .eq('email', body.email)
      .single();

    if (checkError && (checkError as { code?: string }).code !== 'PGRST116') { // PGRST116 = no rows returned
      console.error('Error checking existing user:', checkError);
      return serverError('Failed to check existing user');
    }

    if (existingUser) {
      return badRequest('User with this email already exists');
    }

    // Generate a secure temporary password
    const generateTempPassword = () => {
      const length = 12;
      const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
      let password = '';
      for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
      }
      return password;
    };

    const tempPassword = generateTempPassword();

    // Create user in Supabase Auth with admin client and temporary password
    const { data: authUser, error: authCreateError } = await supabaseAdmin.auth.admin.createUser({
      email: body.email,
      password: tempPassword,
      email_confirm: true, // Set to true since we're providing a password
      user_metadata: {
        first_name: body.firstName,
        last_name: body.lastName,
        role: body.role,
        requires_password_change: true // Flag to force password reset on first login
      }
    });

    if (authCreateError) {
      console.error('Error creating auth user:', authCreateError);
      return serverError('Failed to create user account');
    }

    // minimal log
    
    // Send welcome email with credentials
    try {
      await sendWelcomeEmail({
        email: body.email,
        firstName: body.firstName,
        lastName: body.lastName,
        tempPassword: tempPassword,
      });
      console.warn('Welcome email sent');
    } catch (emailError) {
      console.error('Error sending welcome email:', emailError);
      try {
        await sendEmailFailureAlert({ failedRecipient: body.email, reason: emailError });
        console.warn('Admin alert sent for welcome email failure');
      } catch (alertError) {
        console.error('Failed to send admin alert for email failure:', alertError);
        // Log activity that email failed and alert also failed
        await logActivity(currentUser.id, 'EMAIL_FAILURE', authUser.user.id, {
          failedRecipient: body.email,
          reason: String(emailError),
          alertError: String(alertError),
        });
      }
      // Continue regardless
    }

    // Create user record in database
    const userRecord: DbUserRow = {
      id: authUser.user.id,
      email: body.email,
      first_name: body.firstName,
      last_name: body.lastName,
      role: body.role as UserRole,
      is_active: true,
      email_verified: true,
      assigned_clients: body.assignedClients || null,
      client_id: body.clientId || null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_login_at: null
    };

    const { data: newUser, error: dbError } = await supabaseAdmin
      .from('users')
      .insert([userRecord])
      .select()
      .single();

    if (dbError) {
      console.error('Error creating user record:', dbError);
      // Clean up auth user if database insert fails
      await supabase.auth.admin.deleteUser(authUser.user.id);
      return serverError('Failed to create user record');
    }

    // Log activity
    await logActivity(currentUser.id, 'CREATE_USER', newUser.id, {
      email: body.email,
      firstName: body.firstName,
      lastName: body.lastName,
      role: body.role,
      assignedClients: body.assignedClients,
      clientId: body.clientId
    });

    // Map database response to frontend format
    const mappedUser: User = {
      id: newUser.id,
      email: newUser.email,
      firstName: newUser.first_name,
      lastName: newUser.last_name,
      role: newUser.role as UserRole,
      isActive: newUser.is_active,
      emailVerified: newUser.email_verified,
      assignedClients: newUser.assigned_clients || undefined,
      clientId: newUser.client_id || undefined,
      lastLoginAt: newUser.last_login_at || undefined,
      createdAt: newUser.created_at,
      updatedAt: newUser.updated_at
    };

    return created(mappedUser);
  } catch (error) {
    console.error('Error in POST /api/users:', error);
    return serverError();
  }
}

// Helper function to log activities (bypass RLS)
async function logActivity(userId: string, action: string, targetUserId: string | null, details: unknown) {
  try {
    await supabaseAdmin.from('activity_logs').insert([{
      user_id: userId,
      action,
      target_user_id: targetUserId,
      details,
      timestamp: new Date().toISOString(),
      ip_address: '127.0.0.1', // In production, get from request headers
      user_agent: 'Digital Marketing Portal' // In production, get from request headers
    }]);
  } catch (error) {
    console.error('Failed to log activity:', error);
  }
}
