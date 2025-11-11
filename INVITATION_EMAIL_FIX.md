# Fixing Invitation Email Issues

## Problem
When clicking the invitation email link, users get redirected to `/auth/callback?error=access_denied` instead of setting their password.

## Root Cause
The redirect URL in Supabase's email doesn't match the allowed URLs configured in Supabase Dashboard, OR the URL format in Supabase Dashboard needs to be updated.

## Solution

### Step 1: Update Supabase Dashboard URL Configuration

1. Go to your Supabase Dashboard: https://app.supabase.com
2. Select your project
3. Go to **Authentication** → **URL Configuration**
4. Under **Redirect URLs**, add the following URLs (one per line):
   ```
   http://localhost:3000/auth/callback
   https://hrzociojzzwktexhfnwb.supabase.co/auth/v1/callback
   ```
5. Click **Save**

### Step 2: Verify Email Template

1. Go to **Authentication** → **Email Templates**
2. Confirm the "Invite user" template exists
3. The redirect URL should be: `{{ .SiteURL }}/auth/callback`

### Step 3: Alternative: Use Forgot Password Flow

If the invitation email link still doesn't work, users can:

1. Go to `http://localhost:3000/login`
2. Click "Forgot Password"
3. Enter their email address
4. Set their password via the magic link sent to their email

## Testing

1. Create a new user in the User Management tab
2. Check the email for the user
3. Click the invitation link
4. If successful, they should be redirected to `/dashboard`

## Current Status

The `/auth/callback` page is configured to handle both:
- **Success**: Sets session and redirects to dashboard
- **Error**: Shows helpful message directing users to use "Forgot Password" as fallback

## Notes

- The invitation email link is time-sensitive (expires after a certain period)
- Only one link can be used per user (subsequent clicks will fail)
- If multiple invitation emails are sent, only the most recent one will work



