/**
 * Email utility for sending welcome emails with temporary passwords
 */

import nodemailer from 'nodemailer';

// Simple in-memory rate limit per recipient to avoid accidental bursts
const lastSentByRecipient: Record<string, number> = {};

interface SendWelcomeEmailParams {
  email: string;
  firstName: string;
  lastName: string;
  tempPassword: string;
}

export async function sendWelcomeEmail({
  email,
  firstName,
  lastName,
  tempPassword,
}: SendWelcomeEmailParams): Promise<void> {
  try {
    // Enforce minimum interval between emails to the same user (seconds)
    const minIntervalSec = parseInt(process.env.EMAIL_MIN_INTERVAL_SECONDS || '60', 10);
    const now = Date.now();
    const last = lastSentByRecipient[email] || 0;
    if (now - last < minIntervalSec * 1000) {
      console.warn(`Skipping email to ${email}: sent ${Math.round((now - last) / 1000)}s ago (< ${minIntervalSec}s)`);
      return;
    }

    // Check if SMTP is configured
    const smtpHost = process.env.SMTP_HOST;
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const smtpFrom = process.env.SMTP_FROM;

    if (!smtpHost || !smtpUser || !smtpPass || !smtpFrom) {
      console.warn('SMTP not configured, logging email to console instead');
      logEmailToConsole(email, firstName, lastName, tempPassword);
      return;
    }

    // Create transporter with detailed error handling
    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port: parseInt(process.env.SMTP_PORT || '465'),
      secure: (process.env.SMTP_SECURE || 'true') === 'true',
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
      debug: true, // Enable debug mode for SMTP troubleshooting
      logger: true,
    });

    // Verify connection
    await transporter.verify();
    console.warn('SMTP connection verified successfully');

    // Generate HTML content
    const htmlContent = generateWelcomeEmailHTML(firstName, lastName, email, tempPassword);
    
    // Send email
    const info = await transporter.sendMail({
      from: smtpFrom,
      to: email,
      subject: 'Welcome to Digital Marketing Portal',
      html: htmlContent,
      text: generateWelcomeEmailText(firstName, lastName, email, tempPassword),
    });

    lastSentByRecipient[email] = Date.now();
    console.warn(`Welcome email sent successfully to: ${email}`);
    console.warn(`Message ID: ${info.messageId}`);
    
  } catch (error) {
    console.error('Error sending welcome email:', error);
    console.warn('Falling back to console logging...');
    logEmailToConsole(email, firstName, lastName, tempPassword);
    // Don't throw - we don't want user creation to fail if email fails
  }
}

export async function sendEmailFailureAlert(params: {
  failedRecipient: string;
  reason: unknown;
}): Promise<void> {
  const adminEmail = process.env.ADMIN_ALERT_EMAIL || 'nalluruhaneel@gmail.com';

  const smtpHost = process.env.SMTP_HOST;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const smtpFrom = process.env.SMTP_FROM || smtpUser;

  if (!smtpHost || !smtpUser || !smtpPass || !smtpFrom) {
    console.warn('SMTP not configured for failure alert; skipping admin notification');
    throw new Error('SMTP not configured for failure alert');
  }

  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: parseInt(process.env.SMTP_PORT || '465'),
    secure: (process.env.SMTP_SECURE || 'true') === 'true',
    auth: { user: smtpUser, pass: smtpPass },
    debug: true,
    logger: true,
  });

  await transporter.verify();

  const reasonText = typeof params.reason === 'string' ? params.reason : JSON.stringify(params.reason);
  await transporter.sendMail({
    from: smtpFrom,
    to: adminEmail,
    subject: 'Welcome email delivery failed',
    text: `Failed to deliver welcome email\nRecipient: ${params.failedRecipient}\nReason: ${reasonText}`,
    html: `
      <p><strong>Welcome email delivery failed</strong></p>
      <p><strong>Recipient:</strong> ${params.failedRecipient}</p>
      <p><strong>Reason:</strong> <pre>${reasonText}</pre></p>
    `,
  });
}

function logEmailToConsole(
  email: string,
  firstName: string,
  lastName: string,
  tempPassword: string
): void {
  const emailContent = `
==========================================
WELCOME TO DIGITAL MARKETING PORTAL
==========================================

Dear ${firstName} ${lastName},

Your account has been successfully created!

LOGIN CREDENTIALS:
------------------
Email: ${email}
Temporary Password: ${tempPassword}

IMPORTANT INSTRUCTIONS:
-----------------------
1. Go to: ${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/login
2. Login with your temporary password
3. You will be required to set a new password on your first login
4. After setting your new password, you can access the portal

SECURITY REMINDER:
------------------
- Your temporary password is one-time use only
- You must change it on first login
- Keep your password secure and do not share it

If you have any questions, please contact your administrator.

Best regards,
Digital Marketing Portal Team
==========================================
`;

  console.warn('═══════════════════════════════════════');
  console.warn('📧 WELCOME EMAIL (CONSOLE LOG)');
  console.warn('═══════════════════════════════════════');
  console.warn(`TO: ${email}`);
  console.warn(`SUBJECT: Welcome to Digital Marketing Portal`);
  console.warn('═══════════════════════════════════════');
  console.warn(emailContent);
  console.warn('═══════════════════════════════════════');
}

function generateWelcomeEmailText(
  firstName: string,
  lastName: string,
  email: string,
  tempPassword: string
): string {
  return `
==========================================
WELCOME TO DIGITAL MARKETING PORTAL
==========================================

Dear ${firstName} ${lastName},

Your account has been successfully created!

LOGIN CREDENTIALS:
------------------
Email: ${email}
Temporary Password: ${tempPassword}

IMPORTANT INSTRUCTIONS:
-----------------------
1. Go to: ${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/login
2. Login with your temporary password
3. You will be required to set a new password on your first login
4. After setting your new password, you can access the portal

SECURITY REMINDER:
------------------
- Your temporary password is one-time use only
- You must change it on first login
- Keep your password secure and do not share it

If you have any questions, please contact your administrator.

Best regards,
Digital Marketing Portal Team
==========================================
`;
}

function generateWelcomeEmailHTML(
  firstName: string,
  lastName: string,
  email: string,
  tempPassword: string
): string {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #6366f1; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 30px; border: 1px solid #e5e7eb; }
        .credentials { background: white; padding: 20px; margin: 20px 0; border-left: 4px solid #6366f1; }
        .credentials p { margin: 10px 0; }
        .important { background: #fef3c7; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .button { display: inline-block; padding: 12px 24px; background: #6366f1; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 14px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Welcome to Digital Marketing Portal!</h1>
        </div>
        
        <div class="content">
          <p>Dear ${firstName} ${lastName},</p>
          
          <p>Your account has been successfully created!</p>
          
          <div class="credentials">
            <h3>Your Login Credentials:</h3>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Temporary Password:</strong> ${tempPassword}</p>
          </div>
          
          <div class="important">
            <h4>⚠️ IMPORTANT - First Login Instructions:</h4>
            <ol>
              <li>Click the button below or go to the login page</li>
              <li>Login with your temporary password</li>
              <li>You will be required to set a new permanent password</li>
              <li>This temporary password works only once</li>
            </ol>
          </div>
          
          <a href="${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/login" class="button">
            Go to Login
          </a>
          
          <p><strong>Security Reminder:</strong> Keep your password secure and do not share it with anyone.</p>
          
          <p>If you have any questions, please contact your administrator.</p>
          
          <p>Best regards,<br><strong>Digital Marketing Portal Team</strong></p>
        </div>
        
        <div class="footer">
          This is an automated message. Please do not reply.
        </div>
      </div>
    </body>
    </html>
  `;
}

