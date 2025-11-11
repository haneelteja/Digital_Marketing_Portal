# Fix: Gmail SMTP Error "534 5.7.9 Application-specific password required"

## The Problem

Your Supabase Auth Logs show:
```
Error: 534 5.7.9 Application-specific password required. (gsmtp)
```

This means Gmail is rejecting your SMTP connection because you're using a regular password instead of an **App Password**.

## Solution: Generate Gmail App Password

### Step 1: Enable 2-Step Verification (if not already enabled)
1. Go to: https://myaccount.google.com/security
2. Under "Signing in to Google", check if "2-Step Verification" is ON
3. If OFF, click it and follow the setup process

### Step 2: Generate App Password
1. Go to: https://myaccount.google.com/apppasswords
2. Sign in with `pega2023test@gmail.com`
3. If prompted, select:
   - **App**: Mail
   - **Device**: Other (Custom name)
   - Enter: "Supabase Auth"
4. Click **Generate**
5. You'll see a 16-character password like: `abcd efgh ijkl mnop`
6. **Copy this password** (you can't see it again!)

### Step 3: Update Supabase SMTP Settings
1. Go to **Supabase Dashboard** → **Authentication** → **Emails** → **SMTP Settings**
2. Find the **Password** field
3. **Delete the old password** and paste your new **App Password**
   - You can paste with or without spaces (both work)
   - Example: `abcdefghijklmnop` or `abcd efgh ijkl mnop`
4. Click **"Save changes"**
5. Supabase will test the connection - you should see a success message

### Step 4: Test Password Recovery
1. Go to your login page
2. Click "Forgot Password"
3. Enter an email address
4. Check Supabase Auth Logs again - the error should be gone
5. Check the recipient's inbox (and spam folder)

## Verification

After updating, check Supabase Auth Logs:
- ✅ **Success**: You should see "Password recovery email sent" without errors
- ❌ **Still failing**: Check logs for new error messages

## Alternative: Use a Transactional Email Service

Since Gmail SMTP has limitations, consider switching to a dedicated email service:

### Resend (Recommended)
- **Free tier**: 3,000 emails/month
- **Better deliverability** than Gmail
- **Easy setup**:
  1. Sign up: https://resend.com
  2. Get API key
  3. In Supabase SMTP:
     - Host: `smtp.resend.com`
     - Port: `465`
     - Username: `resend`
     - Password: Your Resend API key

### SendGrid
- **Free tier**: 100 emails/day
- **Host**: `smtp.sendgrid.net`
- **Port**: `587`
- **Username**: `apikey`
- **Password**: Your SendGrid API key

## Why This Happens

Gmail requires App Passwords when:
- 2-Step Verification is enabled (security feature)
- Using SMTP from third-party apps
- Regular passwords don't work for security reasons

## Still Having Issues?

1. **Double-check**: Make sure you copied the App Password correctly
2. **Wait 5 minutes**: Gmail may take a moment to activate the App Password
3. **Check logs**: Look for new error messages in Supabase Auth Logs
4. **Try different email**: Test with a different recipient email
5. **Contact support**: If still failing, share the new error from logs

