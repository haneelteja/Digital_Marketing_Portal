# Supabase Email Invitation Setup

## Issue: "access_denied" Error

When users click the email invitation link, they're getting `access_denied` error.

## Root Cause

Supabase needs to be configured to allow the redirect URL. The email is being sent, but Supabase is rejecting the redirect.

## Solution

### 1. Configure Supabase Redirect URLs

Go to your Supabase Dashboard → Authentication → URL Configuration and add:

- `http://localhost:3000/auth/callback`
- `http://localhost:3000/auth/callback#`

**For production, also add:**
- `https://yourdomain.com/auth/callback`
- `https://yourdomain.com/auth/callback#`

### 2. Alternative: Use Supabase Dashboard to Send Invitations

If the automatic email invitation doesn't work, use the Supabase Dashboard:

1. Go to Supabase Dashboard → Authentication → Users
2. Find the user you want to invite
3. Click "Resend invitation email"
4. This will send the correct invitation link

### 3. Check Email Templates

1. Go to Supabase Dashboard → Authentication → Email Templates
2. Verify the "Invite user" template is active
3. The template should include the proper redirect URL

### 4. Alternative Flow: Manual Setup

If email invitations continue to have issues, you can create users without sending emails:

```typescript
// Just create the user without sending email
const { data: authUser, error: authCreateError } = await supabaseAdmin.auth.admin.createUser({
  email: body.email,
  email_confirm: false,
  user_metadata: {
    first_name: body.firstName,
    last_name: body.lastName,
    role: body.role
  }
});

// User will need to use "Forgot Password" to set their password
```

## Quick Fix

For now, to get invitations working:

1. **Update `.env.local`** with the correct production URL (when deploying)
2. **Add redirect URL** in Supabase Dashboard
3. **Test** by creating a new user and checking the email

The callback page will now show detailed logs in the console to help debug what's being received from the URL.



