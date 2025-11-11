# Gmail & Outlook SMTP Setup Guide

## Overview
This guide will help you configure Gmail or Outlook for sending emails from your application.

## Option 1: Gmail SMTP Setup

### Step 1: Enable 2-Step Verification
1. Go to: https://myaccount.google.com/security
2. Under "Signing in to Google", find "2-Step Verification"
3. If OFF, click it and follow the setup process
4. You'll need your phone for verification

### Step 2: Generate App Password
1. Go to: https://myaccount.google.com/apppasswords
2. Sign in with your Gmail account
3. Select:
   - **App**: Mail
   - **Device**: Other (Custom name)
   - Enter: "Digital Marketing Portal"
4. Click **Generate**
5. Copy the 16-character password (e.g., `abcd efgh ijkl mnop`)
   - ⚠️ **Save this immediately** - you can't see it again!

### Step 3: Configure Supabase SMTP
Go to **Supabase Dashboard** → **Authentication** → **Emails** → **SMTP Settings**:

```
✅ Enable Custom SMTP: ON
Host: smtp.gmail.com
Port: 465 (or 587)
Username: your-email@gmail.com
Password: [Your 16-character App Password]
Sender email: your-email@gmail.com
Sender name: Digital Marketing Portal
```

**Important**: Use the **App Password**, not your regular Gmail password!

### Step 4: Update .env.local
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=your-email@gmail.com
SMTP_PASS=abcdefghijklmnop
SMTP_FROM=your-email@gmail.com
```

Replace:
- `your-email@gmail.com` with your actual Gmail address
- `abcdefghijklmnop` with your App Password (spaces don't matter)

### Step 5: Test Connection
```bash
npm run test:resend
```
(We'll update this script to work with Gmail too)

---

## Option 2: Outlook SMTP Setup

### Step 1: Enable 2-Step Verification
1. Go to: https://account.microsoft.com/security
2. Click "Advanced security options"
3. Enable "Two-step verification"
4. Follow the setup process

### Step 2: Generate App Password
1. Go to: https://account.microsoft.com/security
2. Click "App passwords" (under "Advanced security options")
3. Click "Create a new app password"
4. Enter name: "Digital Marketing Portal"
5. Click "Generate"
6. Copy the password (16 characters)
   - ⚠️ **Save this immediately**!

### Step 3: Configure Supabase SMTP
Go to **Supabase Dashboard** → **Authentication** → **Emails** → **SMTP Settings**:

```
✅ Enable Custom SMTP: ON
Host: smtp-mail.outlook.com
Port: 587
Username: your-email@outlook.com (or @hotmail.com, @live.com)
Password: [Your App Password]
Sender email: your-email@outlook.com
Sender name: Digital Marketing Portal
```

### Step 4: Update .env.local
```env
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@outlook.com
SMTP_PASS=your-app-password
SMTP_FROM=your-email@outlook.com
```

---

## Important Notes

### Gmail Limitations
- ⚠️ **Rate Limits**: Gmail limits to ~500 emails/day for free accounts
- ⚠️ **Deliverability**: May go to spam for transactional emails
- ⚠️ **Not Recommended**: For production with many users
- ✅ **Good For**: Testing, small applications, personal projects

### Outlook Limitations
- ⚠️ **Rate Limits**: Similar to Gmail (~300-500 emails/day)
- ⚠️ **Deliverability**: Better than Gmail but still not ideal
- ✅ **Good For**: Testing, small applications

### Best Practices
1. ✅ Always use App Passwords (never regular passwords)
2. ✅ Enable 2-Step Verification first
3. ✅ Test with a few emails before going live
4. ✅ Monitor for spam folder placement
5. ⚠️ Consider upgrading to a transactional email service for production

---

## Troubleshooting

### Error: "534 5.7.9 Application-specific password required"
- **Solution**: You need to use an App Password, not your regular password
- Generate one at: https://myaccount.google.com/apppasswords (Gmail)
- Or: https://account.microsoft.com/security (Outlook)

### Error: "Invalid login credentials"
- Check that you're using the App Password (not regular password)
- Verify 2-Step Verification is enabled
- Make sure you copied the App Password correctly

### Error: "Connection timeout"
- Try port `587` instead of `465` (Gmail)
- Check firewall/network settings
- Verify SMTP server address is correct

### Emails going to spam
- This is common with Gmail/Outlook SMTP
- Consider using a transactional email service for better deliverability
- Add SPF/DKIM records if you have a domain

---

## Quick Reference

### Gmail SMTP Settings
```
Host: smtp.gmail.com
Port: 465 (SSL) or 587 (TLS)
Secure: true (for 465) or false (for 587)
Username: your-email@gmail.com
Password: [App Password]
```

### Outlook SMTP Settings
```
Host: smtp-mail.outlook.com
Port: 587
Secure: false
Username: your-email@outlook.com
Password: [App Password]
```

---

## Which Should You Use?

**Gmail** if:
- You already have a Gmail account
- You're comfortable with Google's security
- You need quick setup

**Outlook** if:
- You prefer Microsoft services
- You have an Outlook/Hotmail account
- You want an alternative to Gmail

**Both work**, but remember:
- ⚠️ Rate limits apply
- ⚠️ Deliverability may be lower than professional services
- ✅ Good for testing and small applications







