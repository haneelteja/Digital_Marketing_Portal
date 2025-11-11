# Gmail SMTP Setup - App Password Required

## Problem
Gmail is rejecting your login because regular passwords don't work with SMTP. You need to use an **App Password**.

## Error Message
```
Error: Invalid login: 535-5.7.8 Username and Password not accepted.
```

## Solution: Create a Gmail App Password

### Step 1: Enable 2-Factor Authentication
1. Go to your Google Account: https://myaccount.google.com/
2. Go to **Security** → **2-Step Verification**
3. Enable 2-Factor Authentication (if not already enabled)

### Step 2: Generate App Password
1. Go to: https://myaccount.google.com/apppasswords
2. Sign in with your Gmail account
3. Under "Select app", choose **Mail**
4. Under "Select device", choose **Other** and type "Digital Marketing Portal"
5. Click **Generate**
6. Copy the 16-character password (spaces don't matter)

### Step 3: Update Your .env.local File
Replace the `SMTP_PASS` value with your new App Password:

```env
# Update this line in your .env.local file:
SMTP_PASS=abcd efgh ijkl mnop
# Or without spaces:
SMTP_PASS=abcdefghijklmnop
```

### Step 4: Restart the Dev Server
After updating `.env.local`, restart your Next.js dev server:

```bash
# Kill any running node processes
taskkill /F /IM node.exe

# Start the dev server
npm run dev
```

## Alternative: Use Different Email Provider
If you don't want to use Gmail App Passwords, consider:
- **Resend** (API-based, no SMTP needed)
- **SendGrid** (free tier available)
- **Mailgun** (API-based)

## Testing
After updating your `.env.local` file with the App Password:
1. Create a new user in User Management
2. Check the server console for: `✅ SMTP connection verified successfully`
3. Check the recipient's inbox for the welcome email



