import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';

/**
 * POST /api/users/check-email
 * Check if a user exists and is active (public endpoint for password recovery)
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email } = body;

    if (!email || typeof email !== 'string') {
      return NextResponse.json(
        { error: 'Email is required' },
        { status: 400 }
      );
    }

    // Check if user exists in the users table
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('id, email, is_active, role')
      .eq('email', email.toLowerCase().trim())
      .single();

    if (userError || !userData) {
      // User doesn't exist in database
      return NextResponse.json({
        exists: false,
        isActive: false,
        message: 'This email address is not registered.'
      });
    }

    // Check if user exists in auth.users by trying to get user by email
    // This is more efficient than listing all users
    let existsInAuth = false;
    try {
      const { data: authUsers, error: authError } = await supabaseAdmin.auth.admin.listUsers();
      if (!authError && authUsers) {
        existsInAuth = authUsers.users.some(user => 
          user.email?.toLowerCase() === email.toLowerCase().trim()
        );
      }
    } catch (authCheckError) {
      // If we can't check auth, assume it exists (fail open for better UX)
      console.warn('Could not verify auth user existence:', authCheckError);
      existsInAuth = true; // Assume exists to allow password reset attempt
    }

    // Return user status
    return NextResponse.json({
      exists: true,
      existsInAuth: existsInAuth,
      isActive: userData.is_active,
      message: userData.is_active
        ? (existsInAuth 
            ? 'User account is active and ready for password recovery.'
            : 'User exists but account setup may be incomplete. Please contact your administrator.')
        : 'Your account is inactive. Please contact your administrator to activate your account.'
    });
  } catch (error) {
    console.error('Error checking user email:', error);
    return NextResponse.json(
      { error: 'Failed to check user status' },
      { status: 500 }
    );
  }
}

