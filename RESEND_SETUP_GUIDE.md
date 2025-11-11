# Resend Email Setup Guide

## Overview
This guide will help you configure Resend for email sending in both:
1. **Supabase Auth** (for password recovery emails)
2. **Application** (for welcome/invitation emails)

## Step 1: Sign Up for Resend

1. Go to: https://resend.com
2. Sign up for a free account (3,000 emails/month free)
3. Verify your email address

## Step 2: Get Your Resend API Key

1. Go to: https://resend.com/api-keys
2. Click **"Create API Key"**
3. Give it a name: "Digital Marketing Portal"
4. Copy the API key (starts with `re_...`)
   - ⚠️ **Save this immediately** - you can't see it again!

## Step 3: Verify Your Domain (Optional but Recommended)

For production, verify your domain:
1. Go to: https://resend.com/domains
2. Click **"Add Domain"**
3. Follow the DNS setup instructions
4. Once verified, you can send from `noreply@yourdomain.com`

For testing, you can use Resend's test domain: `onboarding@resend.dev`

## Step 4: Configure Supabase SMTP Settings

This is for **password recovery emails** sent by Supabase:

1. Go to **Supabase Dashboard** → **Authentication** → **Emails** → **SMTP Settings**
2. Enable **"Enable Custom SMTP"**
3. Fill in the following:
   - **Host**: `smtp.resend.com`
   - **Port**: `465` (or `587` for TLS)
   - **Username**: `resend`
   - **Password**: Your Resend API key (the `re_...` key you copied)
   - **Sender email**: Use a verified domain email or `onboarding@resend.dev` for testing
   - **Sender name**: `Digital Marketing Portal` (or your preferred name)
4. Click **"Save changes"**
5. Supabase will test the connection - you should see a success message ✅

## Step 5: Configure Application SMTP (for Welcome Emails)

The application uses `lib/email.ts` to send welcome emails. Update your environment variables:

### Option A: Using `.env.local` (Development)

Create or update `.env.local` in your project root:

```env
# Resend SMTP Configuration
SMTP_HOST=smtp.resend.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=resend
SMTP_PASS=re_YOUR_API_KEY_HERE
SMTP_FROM=onboarding@resend.dev
# Or use your verified domain: noreply@yourdomain.com

# Email Settings
EMAIL_MIN_INTERVAL_SECONDS=60
ADMIN_ALERT_EMAIL=your-admin@email.com
```

### Option B: Using Environment Variables (Production)

Set these in your hosting platform (Vercel, Railway, etc.):
- `SMTP_HOST=smtp.resend.com`
- `SMTP_PORT=465`
- `SMTP_SECURE=true`
- `SMTP_USER=resend`
- `SMTP_PASS=re_YOUR_API_KEY_HERE`
- `SMTP_FROM=onboarding@resend.dev` (or your verified domain)

## Step 6: Test the Connection

### Test Supabase SMTP Connection
1. After saving SMTP settings in Supabase, it should show "Connection successful"
2. Go to **Authentication** → **Users**
3. Find a test user
4. Click **"Send password recovery email"**
5. Check the email inbox (and spam folder)

### Test Application Email
1. Restart your dev server: `npm run dev`
2. Create a new user in User Management
3. Check the server console for: `✅ SMTP connection verified successfully`
4. Check the recipient's inbox for the welcome email

## Step 7: Verify Email Delivery

### Check Resend Dashboard
1. Go to: https://resend.com/emails
2. You should see all sent emails
3. Check delivery status, opens, clicks, etc.

### Check Supabase Auth Logs
1. Go to **Supabase Dashboard** → **Authentication** → **Logs**
2. Look for password recovery attempts
3. Should see "Password recovery email sent" without errors

## Troubleshooting

### Error: "Invalid credentials"
- Double-check your Resend API key
- Make sure you're using `resend` as the username
- Verify the API key is active in Resend dashboard

### Error: "Connection timeout"
- Check your firewall/network settings
- Try port `587` instead of `465`
- Verify Resend service status: https://status.resend.com

### Emails not arriving
- Check Resend dashboard for delivery status
- Check spam/junk folder
- Verify sender email is correct
- Check Resend logs for bounce/spam reports

### Application emails not sending
- Verify `.env.local` has all SMTP variables
- Restart dev server after updating `.env.local`
- Check server console for error messages
- Verify `SMTP_FROM` email is valid

## Resend API Limits

- **Free tier**: 3,000 emails/month
- **Rate limit**: 10 emails/second
- **Upgrade**: If you need more, upgrade at https://resend.com/pricing

## Security Best Practices

1. ✅ Never commit API keys to git
2. ✅ Use environment variables for all sensitive data
3. ✅ Rotate API keys periodically
4. ✅ Monitor Resend dashboard for suspicious activity
5. ✅ Use verified domains for production

## Next Steps

After setup:
1. Test password recovery flow
2. Test user invitation flow
3. Monitor Resend dashboard for delivery rates
4. Set up domain verification for production
5. Configure email templates in Supabase (optional)

