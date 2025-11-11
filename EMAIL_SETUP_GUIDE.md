# Email Invitation Setup Guide

## Overview
This guide explains how the email invitation system works in the Digital Marketing Portal and how to configure it properly.

## How It Works

When an IT Admin creates a new user through the User Management tab, the system:
1. Creates the user account in Supabase Auth
2. Automatically sends an invitation email to the new user
3. The email contains a secure link for the user to set up their password

## Configuration Required

### 1. Environment Variables

Add the following to your `.env.local` file:

```bash
# Supabase Configuration (Client)
NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key

# Supabase Service Role Key (Server-Side Admin Operations)
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

# Application URLs
NEXT_PUBLIC_APP_URL=http://localhost:3000  # For local development
NEXT_PUBLIC_SITE_URL=https://your-domain.com  # For production
```

### 2. Getting Your Service Role Key

1. Go to your [Supabase Dashboard](https://supabase.com/dashboard)
2. Select your project
3. Go to **Settings** → **API**
4. Find the **Service Role Key** (keep this secret!)
5. Copy it to your `.env.local` file as `SUPABASE_SERVICE_ROLE_KEY`

⚠️ **Important:** Never expose the service role key in client-side code or commit it to version control!

### 3. Configure Email Templates (Optional)

To customize the invitation email:

1. Go to **Authentication** → **Email Templates**
2. Select **Invite user**
3. Customize the email content
4. Use variables like:
   - `{{ .Email }}` - User's email
   - `{{ .Token }}` - Invitation token
   - `{{ .TokenHash }}` - Hashed token
   - `{{ .ConfirmationURL }}` - Confirmation link

### 4. Test Email Configuration

To test if emails are being sent:

1. Create a test user with a valid email address
2. Check your Supabase Dashboard logs: **Logs** → **Auth Logs**
3. Look for email sending events
4. If you see errors, check the **Auth Logs** for details

## Troubleshooting

### Emails Not Being Sent

**Problem:** Users are created but no emails are received.

**Solutions:**

1. **Check Supabase Email Configuration:**
   - Go to **Project Settings** → **Auth** → **Email**
   - Ensure email sending is enabled
   - Configure SMTP settings if using custom SMTP

2. **Verify Service Role Key:**
   ```bash
   # Ensure .env.local has the service role key
   echo $SUPABASE_SERVICE_ROLE_KEY
   ```

3. **Check Console Logs:**
   - When creating a user, check the browser console
   - Look for: "Invitation email sent successfully to: [email]"
   - Or: "Error sending invitation email: [error]"

4. **Check Supabase Auth Logs:**
   - Go to **Authentication** → **Users** → **Logs**
   - Look for email events and any error messages

5. **Email Provider Settings:**
   - Check if emails are going to spam/junk folder
   - Verify the sender email is properly configured in Supabase
   - For custom SMTP, ensure credentials are correct

### Email Template Issues

**Problem:** Emails are sent but look wrong or are blank.

**Solutions:**

1. Go to **Authentication** → **Email Templates**
2. Reset to default templates if needed
3. Ensure all required variables are included
4. Test with a simple template first

### Missing Service Role Key Error

**Problem:** "Missing SUPABASE_SERVICE_ROLE_KEY" error.

**Solutions:**

1. Add the service role key to `.env.local`:
   ```bash
   SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here
   ```

2. Restart your development server:
   ```bash
   npm run dev
   ```

3. For production, add the key to your hosting platform's environment variables

## Development vs Production

### Development (Local)
- Uses Supabase's default email service
- All emails go to the configured test email or your email provider
- No custom SMTP required for testing

### Production
- Configure custom SMTP for better deliverability
- Set up proper email domain (SPF, DKIM records)
- Use a transactional email service (SendGrid, Mailgun, etc.)
- Update `NEXT_PUBLIC_SITE_URL` to your production domain

## Security Best Practices

1. ✅ Keep service role key secure and never expose it
2. ✅ Use environment variables for all sensitive data
3. ✅ Enable email verification in production
4. ✅ Implement rate limiting on user creation
5. ✅ Monitor auth logs for suspicious activity
6. ✅ Use HTTPS in production

## Code Implementation

### Files Modified
- `lib/supabaseAdmin.ts` - Server-side Supabase client with service role
- `src/app/api/users/route.ts` - User creation with email invitation

### Key Changes
1. Created admin Supabase client with service role key
2. Switched from `supabase.auth.admin` to `supabaseAdmin.auth.admin`
3. Call `inviteUserByEmail()` after user creation
4. Wrapped email sending in try-catch for graceful failures

## Support

For additional help:
- [Supabase Auth Documentation](https://supabase.com/docs/guides/auth)
- [Supabase Email Configuration](https://supabase.com/docs/guides/auth/auth-email)
- Check Supabase Dashboard logs for detailed error messages



