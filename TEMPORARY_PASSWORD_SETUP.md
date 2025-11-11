# Temporary Password Implementation

## Overview
Users are now created with a temporary password that is logged to the console. In production, you'll need to configure an email service to send this password to users.

## Current Implementation

### ✅ What's Working
1. **Random Password Generation**: Creates a secure 12-character password with mixed case, numbers, and special characters
2. **User Creation**: Creates the user in Supabase Auth with the temporary password
3. **Console Logging**: Temporary password is printed to console for testing

### 📝 Console Output
When creating a new user, you'll see:
```
IMPORTANT - Temporary password for user@example.com : Ab3$kL9#mN2x
In production, send this via email service (SendGrid, Resend, etc.)
```

## Production Setup - Send Email with Password

### Option 1: Using Resend (Recommended)

#### 1. Install Resend
```bash
npm install resend
```

#### 2. Add to `.env.local`
```env
RESEND_API_KEY=re_xxxxxxxxxxxxx
```

#### 3. Create Email Helper (`lib/email.ts`)
```typescript
import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendPasswordEmail(
  email: string,
  firstName: string,
  tempPassword: string
) {
  try {
    await resend.emails.send({
      from: 'noreply@yourdomain.com',
      to: email,
      subject: 'Your Digital Marketing Portal Account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Welcome to Digital Marketing Portal!</h2>
          <p>Hello ${firstName},</p>
          <p>Your account has been created. Here are your login credentials:</p>
          <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Temporary Password:</strong> ${tempPassword}</p>
          </div>
          <p>Please login at: <a href="${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/login">Login Page</a></p>
          <p><strong>Important:</strong> Please change your password after first login using the "Forgot Password" option.</p>
          <p>Best regards,<br>Digital Marketing Portal Team</p>
        </div>
      `
    });
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
}
```

#### 4. Update `src/app/api/users/route.ts`
Add import at top:
```typescript
import { sendPasswordEmail } from '../../../lib/email';
```

Replace the TODO section with:
```typescript
// Send email with temporary password
try {
  await sendPasswordEmail(body.email, body.firstName, tempPassword);
  console.log('Password email sent successfully to:', body.email);
} catch (emailError) {
  console.error('Error sending password email:', emailError);
  // User is created, but email failed - log it
}
```

### Option 2: Using SendGrid

#### 1. Install SendGrid
```bash
npm install @sendgrid/mail
```

#### 2. Add to `.env.local`
```env
SENDGRID_API_KEY=SG.xxxxxxxxxxxxx
```

#### 3. Create Email Helper
```typescript
import sgMail from '@sendgrid/mail';

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

export async function sendPasswordEmail(
  email: string,
  firstName: string,
  tempPassword: string
) {
  const msg = {
    to: email,
    from: 'noreply@yourdomain.com',
    subject: 'Your Digital Marketing Portal Account',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome to Digital Marketing Portal!</h2>
        <p>Hello ${firstName},</p>
        <p>Your account has been created. Here are your login credentials:</p>
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Temporary Password:</strong> ${tempPassword}</p>
        </div>
        <p>Please login at: <a href="${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/login">Login Page</a></p>
        <p><strong>Important:</strong> Please change your password after first login.</p>
      </div>
    `
  };

  try {
    await sgMail.send(msg);
    console.log('Password email sent successfully to:', email);
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
}
```

## How It Works

### User Creation Flow
1. **Generate Password**: Creates a random 12-character secure password
2. **Create User**: Creates Supabase user with this password
3. **Set Flag**: Adds `temp_password: true` to user metadata
4. **Send Email**: (Production only) Sends email with credentials
5. **User Login**: User logs in with temporary password
6. **Change Password**: User should use "Forgot Password" to set a new password

### Testing
1. Create a new user from the User Management tab
2. Check the terminal/server logs for: `IMPORTANT - Temporary password for user@example.com : xxxxxxx`
3. Login with that email and password
4. Use "Forgot Password" to set a permanent password

## Security Notes

1. **Temporary passwords are logged in development only**
2. **In production, remove console.log statements**
3. **Passwords expire after 30 days** (Supabase default)
4. **Users should be prompted to change password on first login**
5. **Email sending should be configured with a verified sender domain**

## Next Steps

1. Choose an email service (Resend or SendGrid)
2. Get API key and add to `.env.local`
3. Implement the email sending function
4. Test with real email addresses
5. Configure verified sender domain for production



