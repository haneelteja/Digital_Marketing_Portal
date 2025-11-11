# Email Delivery Troubleshooting Guide

## Problem: Supabase Says Email Sent, But Email Not Received

If you see "A password reset link has been sent to your email" but the email never arrives, follow these steps:

## Step 1: Check Supabase Auth Logs

1. Go to **Supabase Dashboard** → **Authentication** → **Logs**
2. Look for recent password reset attempts
3. Check for any error messages or warnings
4. Look for entries like:
   - "Password recovery email sent"
   - "SMTP connection failed"
   - "Email delivery error"

## Step 2: Verify SMTP Connection

1. Go to **Supabase Dashboard** → **Authentication** → **Emails** → **SMTP Settings**
2. Click "Test SMTP Connection" or "Save changes" (which will test the connection)
3. Check for any error messages
4. Common errors:
   - **"Invalid login"** → You need a Gmail App Password (not regular password)
   - **"Connection timeout"** → Check firewall/network settings
   - **"Authentication failed"** → Wrong password or App Password not set up

## Step 3: Check These Common Issues

### Issue 1: Gmail App Password Required
- Gmail requires an **App Password** for SMTP (not your regular password)
- Generate one at: https://myaccount.google.com/apppasswords
- Update it in Supabase SMTP Settings

### Issue 2: Emails Going to Spam
- Check the recipient's **Spam/Junk folder**
- Check **Promotions** tab in Gmail
- Check **All Mail** folder
- The email might be filtered by Gmail's algorithms

### Issue 3: Gmail Rate Limiting
- Gmail has strict limits on outgoing emails
- If you send too many emails, Gmail may temporarily block
- Wait 15-30 minutes and try again

### Issue 4: Email Address Verification
- Verify the email address is correct
- Check for typos
- Try sending to a different email address to test

### Issue 5: Gmail Blocking Transactional Emails
- Gmail SMTP is designed for personal emails, not transactional
- Gmail may block or delay transactional emails
- **Solution**: Use a dedicated email service (see Step 4)

## Step 4: Alternative Email Services (Recommended for Production)

For better deliverability, consider switching to a transactional email service:

### Option A: Resend (Recommended - Easy Setup)
1. Sign up at https://resend.com (free tier available)
2. Get API key
3. In Supabase → **Authentication** → **Emails** → **SMTP Settings**:
   - Host: `smtp.resend.com`
   - Port: `465` or `587`
   - Username: `resend`
   - Password: Your Resend API key
   - Sender email: Use a verified domain email

### Option B: SendGrid
1. Sign up at https://sendgrid.com (free tier: 100 emails/day)
2. Create SMTP credentials
3. Use in Supabase SMTP Settings

### Option C: Mailgun
1. Sign up at https://mailgun.com
2. Get SMTP credentials
3. Use in Supabase SMTP Settings

## Step 5: Manual Workaround (For Testing)

If emails aren't working, you can manually generate a password reset link:

1. Go to **Supabase Dashboard** → **Authentication** → **Users**
2. Find the user
3. Click on the user
4. Click **"Send password recovery email"** (this uses Supabase's built-in email system)
5. Or manually reset password in the user details

## Step 6: Verify Email Template

1. Go to **Supabase Dashboard** → **Authentication** → **Email Templates**
2. Check **"Reset Password"** template
3. Ensure it has the correct redirect URL: `{{ .ConfirmationURL }}`
4. Test the template

## Step 7: Check Redirect URL Configuration

1. Go to **Supabase Dashboard** → **Authentication** → **URL Configuration**
2. Ensure these are added:
   - `http://localhost:3000/auth/callback` (for development)
   - `https://yourdomain.com/auth/callback` (for production)
3. Without these, the reset link won't work even if email is received

## Testing Checklist

- [ ] SMTP connection test passes in Supabase
- [ ] Using Gmail App Password (not regular password)
- [ ] Checked spam/junk folder
- [ ] Checked Supabase Auth Logs for errors
- [ ] Verified recipient email address is correct
- [ ] Redirect URLs are configured in Supabase
- [ ] Email template is properly configured

## Still Not Working?

If emails still don't arrive after checking all the above:

1. **Check Supabase Auth Logs** for specific error messages
2. **Try a different email provider** (Gmail SMTP is unreliable for transactional emails)
3. **Contact Supabase Support** with logs and error details
4. **Use Manual Password Reset** as a temporary workaround

