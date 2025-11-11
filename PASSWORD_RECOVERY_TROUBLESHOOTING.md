# Password Recovery Troubleshooting Guide

## Error: "Error sending recovery email" (500 Error)

This error occurs when Supabase cannot send the password recovery email. Common causes and solutions:

### 1. Email Not Configured in Supabase

**Symptom:** 500 error when clicking "Forgot Password"

**Solution:**
1. Go to Supabase Dashboard → Authentication → Email Templates
2. Check if email templates are configured
3. If using custom SMTP:
   - Go to Settings → Auth → SMTP Settings
   - Configure your SMTP server details
   - Test the connection

### 2. User Doesn't Exist in Supabase Auth

**Symptom:** Email exists in database but not in `auth.users`

**Solution:**
1. Check Supabase Dashboard → Authentication → Users
2. Verify the email exists in `auth.users` table
3. If user exists in `users` table but not in `auth.users`:
   - User needs to be created via User Management (IT Admin)
   - Or manually invite via Supabase Dashboard

### 3. Email Service Rate Limiting

**Symptom:** Error after multiple attempts

**Solution:**
- Wait 5-10 minutes before trying again
- Supabase has rate limits to prevent abuse

### 4. Redirect URL Not Configured

**Symptom:** Email sends but callback fails

**Solution:**
1. Go to Supabase Dashboard → Authentication → URL Configuration
2. Add redirect URL: `http://localhost:3000/auth/callback` (for development)
3. For production, add: `https://yourdomain.com/auth/callback`

## Checking User Status

### Check if User Exists in Auth

Run this SQL query in Supabase SQL Editor:

```sql
SELECT 
    id,
    email,
    created_at,
    email_confirmed_at,
    confirmed_at,
    encrypted_password IS NOT NULL as has_password
FROM auth.users
WHERE email = 'user@example.com';
```

### Check if User Exists in Database

```sql
SELECT 
    id,
    email,
    first_name,
    last_name,
    role,
    is_active
FROM users
WHERE email = 'user@example.com';
```

## Workaround: Admin Password Reset

If email recovery is not working, IT Admins can:

1. Go to User Management
2. Edit the user
3. Change their password temporarily
4. Have them log in with the temporary password
5. They will be prompted to set a new password

## Alternative: Manual Invitation

1. Go to Supabase Dashboard → Authentication → Users
2. Click "Invite User"
3. Enter the email address
4. User will receive an invitation email with a link to set their password

## Testing Email Configuration

1. Go to Supabase Dashboard → Authentication → Email Templates
2. Click on "Reset password" template
3. Preview the template
4. Check if SMTP is configured (Settings → Auth → SMTP Settings)

## Contact Information

If issues persist:
- Check Supabase Dashboard logs: Project Settings → Logs
- Verify email service status on Supabase status page
- Contact Supabase support if it's a platform issue


