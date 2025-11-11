# Resend Email Restrictions & Domain Verification

## Current Status: Test Domain Limitations

### ⚠️ Test Domain Restriction
When using Resend's **test domain** (`onboarding@resend.dev`):
- ✅ Can send to: **Your account email only** (`nalluruhaneel@gmail.com`)
- ❌ Cannot send to: Any other email addresses

This is why the test email worked, but you'll get errors if you try to send to other recipients.

## Solution: Verify Your Domain

To send emails to **ANY recipient**, you need to:

### Step 1: Verify Your Domain in Resend
1. Go to: https://resend.com/domains
2. Click **"Add Domain"**
3. Enter your domain (e.g., `yourdomain.com`)
4. Follow the DNS setup instructions

### Step 2: Add DNS Records
Resend will provide DNS records to add:
- **SPF Record**: Authorizes Resend to send emails
- **DKIM Record**: Verifies email authenticity
- **DMARC Record** (optional): Email security policy

Add these to your domain's DNS settings (usually in your domain registrar or hosting provider).

### Step 3: Wait for Verification
- DNS propagation can take 24-48 hours
- Resend will show verification status
- Once verified, you'll see a green checkmark ✅

### Step 4: Update Configuration
After domain verification:

#### Update `.env.local`:
```env
SMTP_FROM=noreply@yourdomain.com
# Or
SMTP_FROM=no-reply@yourdomain.com
```

#### Update Supabase SMTP Settings:
- **Sender email**: `noreply@yourdomain.com` (or your verified domain email)
- Keep other settings the same

## What Happens After Domain Verification?

Once your domain is verified:
- ✅ Can send to **ANY email address**
- ✅ Better deliverability (emails less likely to go to spam)
- ✅ Professional sender address (your domain instead of `onboarding@resend.dev`)
- ✅ Higher sending limits
- ✅ Full production capabilities

## Current Workaround (For Testing)

If you need to test with other emails **before** domain verification:

1. **Option 1**: Use your account email (`nalluruhaneel@gmail.com`) for all test recipients
2. **Option 2**: Add test users with `nalluruhaneel@gmail.com` as their email temporarily
3. **Option 3**: Wait for domain verification (recommended for production)

## Production Checklist

Before going live:
- [ ] Verify domain in Resend
- [ ] Update `SMTP_FROM` in `.env.local` to use verified domain
- [ ] Update Supabase SMTP sender email to verified domain
- [ ] Test sending to various email providers (Gmail, Outlook, etc.)
- [ ] Monitor Resend dashboard for delivery rates
- [ ] Check spam folder placement

## Quick Reference

| Setup Type | Sender Email | Can Send To | Use Case |
|------------|--------------|-------------|----------|
| **Test Domain** | `onboarding@resend.dev` | Account owner only | Development/Testing |
| **Verified Domain** | `noreply@yourdomain.com` | **Any email address** | Production |

## Need Help?

- **Resend Domain Setup**: https://resend.com/docs/dashboard/domains/introduction
- **DNS Configuration**: Check with your domain registrar
- **Resend Support**: https://resend.com/support







