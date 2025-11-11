# Resend Quick Setup Checklist

## ✅ Step-by-Step Setup

### 1. Get Resend API Key
- [ ] Sign up at https://resend.com
- [ ] Go to https://resend.com/api-keys
- [ ] Create API key: "Digital Marketing Portal"
- [ ] Copy the key (starts with `re_...`)

### 2. Configure Supabase SMTP
- [ ] Go to **Supabase Dashboard** → **Authentication** → **Emails** → **SMTP Settings**
- [ ] Enable **"Enable Custom SMTP"**
- [ ] Set **Host**: `smtp.resend.com`
- [ ] Set **Port**: `465`
- [ ] Set **Username**: `resend`
- [ ] Set **Password**: Your Resend API key (`re_...`)
- [ ] Set **Sender email**: `onboarding@resend.dev` (or your verified domain)
- [ ] Set **Sender name**: `Digital Marketing Portal`
- [ ] Click **"Save changes"**
- [ ] ✅ Verify connection test passes

### 3. Configure Application Environment
- [ ] Create/update `.env.local` file
- [ ] Add these variables:
  ```env
  SMTP_HOST=smtp.resend.com
  SMTP_PORT=465
  SMTP_SECURE=true
  SMTP_USER=resend
  SMTP_PASS=re_YOUR_API_KEY_HERE
  SMTP_FROM=onboarding@resend.dev
  ```
- [ ] Replace `re_YOUR_API_KEY_HERE` with your actual Resend API key

### 4. Install Dependencies (if needed)
```bash
npm install dotenv
```

### 5. Test Connection
```bash
npm run test:resend
```

### 6. Test Password Recovery
- [ ] Go to login page
- [ ] Click "Forgot Password"
- [ ] Enter test email
- [ ] Check Supabase Auth Logs for success
- [ ] Check email inbox (and spam folder)

### 7. Test User Invitation
- [ ] Create a new user in User Management
- [ ] Check server console for: `✅ SMTP connection verified successfully`
- [ ] Check recipient's inbox for welcome email

## 🎯 Quick Reference

### Supabase SMTP Settings
```
Host: smtp.resend.com
Port: 465
Username: resend
Password: [Your Resend API Key]
Sender: onboarding@resend.dev
```

### Environment Variables (.env.local)
```env
SMTP_HOST=smtp.resend.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=resend
SMTP_PASS=re_YOUR_API_KEY
SMTP_FROM=onboarding@resend.dev
```

## 🔍 Verification

After setup, verify:
- [ ] Supabase SMTP connection test passes
- [ ] `npm run test:resend` succeeds
- [ ] Password recovery emails are sent
- [ ] Welcome emails are sent
- [ ] Check Resend dashboard: https://resend.com/emails

## ❌ Troubleshooting

**Connection fails:**
- Verify API key is correct
- Check username is exactly `resend`
- Try port `587` instead of `465`

**Emails not arriving:**
- Check Resend dashboard for delivery status
- Check spam/junk folder
- Verify sender email is correct

**Application emails not working:**
- Restart dev server after updating `.env.local`
- Check server console for errors
- Verify all SMTP_* variables are set

