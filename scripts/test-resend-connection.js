/**
 * Test Resend SMTP Connection
 * 
 * This script tests the Resend SMTP connection using the same
 * configuration as the application.
 * 
 * Usage:
 *   node scripts/test-resend-connection.js
 * 
 * Make sure you have SMTP_* environment variables set in .env.local
 */

// Load environment variables from .env.local
const path = require('path');
const fs = require('fs');

// Try to load dotenv
let dotenvLoaded = false;
try {
  const dotenv = require('dotenv');
  const envPath = path.resolve(process.cwd(), '.env.local');
  
  if (fs.existsSync(envPath)) {
    const result = dotenv.config({ path: envPath });
    if (!result.error) {
      dotenvLoaded = true;
      console.log('✅ Loaded .env.local file');
    } else {
      console.warn('⚠️  Warning: Error loading .env.local:', result.error.message);
    }
  } else {
    console.warn('⚠️  Warning: .env.local file not found at:', envPath);
  }
} catch (e) {
  console.warn('⚠️  Warning: dotenv not available. Make sure SMTP_* environment variables are set.');
}

const nodemailer = require('nodemailer');

async function testResendConnection() {
  console.log('🧪 Testing Resend SMTP Connection...\n');

  // Get configuration from environment variables
  const smtpHost = process.env.SMTP_HOST || 'smtp.resend.com';
  const smtpPort = parseInt(process.env.SMTP_PORT || '465', 10);
  const smtpSecure = (process.env.SMTP_SECURE || 'true') === 'true';
  const smtpUser = process.env.SMTP_USER || 'resend';
  const smtpPass = process.env.SMTP_PASS;
  const smtpFrom = process.env.SMTP_FROM || 'onboarding@resend.dev';
  // Resend test domain can only send to account owner's email
  // For production, verify a domain at resend.com/domains
  const testEmail = process.env.TEST_EMAIL || process.env.ADMIN_ALERT_EMAIL || 'nalluruhaneel@gmail.com';

  // Validate configuration
  if (!smtpPass) {
    console.error('❌ Error: SMTP_PASS environment variable is not set!');
    console.error('\nPlease set SMTP_PASS in your .env.local file:');
    console.error('SMTP_PASS=re_YOUR_RESEND_API_KEY');
    process.exit(1);
  }

  console.log('📋 Configuration:');
  console.log(`   Host: ${smtpHost}`);
  console.log(`   Port: ${smtpPort}`);
  console.log(`   Secure: ${smtpSecure}`);
  console.log(`   Username: ${smtpUser}`);
  console.log(`   Password: ${smtpPass.substring(0, 10)}...${smtpPass.substring(smtpPass.length - 4)}`);
  console.log(`   From: ${smtpFrom}`);
  console.log(`   Test Email: ${testEmail}\n`);

  // Create transporter
  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
    debug: true,
    logger: true,
  });

  try {
    // Test connection
    console.log('🔌 Testing SMTP connection...');
    await transporter.verify();
    console.log('✅ SMTP connection verified successfully!\n');

    // Send test email
    console.log('📧 Sending test email...');
    const info = await transporter.sendMail({
      from: smtpFrom,
      to: testEmail,
      subject: 'Resend SMTP Connection Test',
      text: `
This is a test email from the Digital Marketing Portal.

If you received this email, your Resend SMTP configuration is working correctly!

Configuration:
- Host: ${smtpHost}
- Port: ${smtpPort}
- Secure: ${smtpSecure}
- From: ${smtpFrom}

Test completed at: ${new Date().toISOString()}
      `,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #6366f1; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { background: #f9fafb; padding: 30px; border: 1px solid #e5e7eb; }
            .success { background: #d1fae5; padding: 15px; border-radius: 8px; margin: 20px 0; }
            .config { background: white; padding: 15px; margin: 20px 0; border-left: 4px solid #6366f1; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>✅ Resend SMTP Connection Test</h1>
            </div>
            <div class="content">
              <div class="success">
                <h3>🎉 Success!</h3>
                <p>Your Resend SMTP configuration is working correctly!</p>
              </div>
              <div class="config">
                <h3>Configuration Details:</h3>
                <p><strong>Host:</strong> ${smtpHost}</p>
                <p><strong>Port:</strong> ${smtpPort}</p>
                <p><strong>Secure:</strong> ${smtpSecure}</p>
                <p><strong>From:</strong> ${smtpFrom}</p>
                <p><strong>Test Time:</strong> ${new Date().toISOString()}</p>
              </div>
              <p>You can now use this configuration for sending emails from your application.</p>
            </div>
          </div>
        </body>
        </html>
      `,
    });

    console.log('✅ Test email sent successfully!');
    console.log(`   Message ID: ${info.messageId}`);
    console.log(`   To: ${testEmail}`);
    console.log(`   From: ${smtpFrom}\n`);
    console.log('📬 Check your inbox (and spam folder) for the test email.');
    console.log('📊 You can also check the Resend dashboard: https://resend.com/emails\n');
    console.log('ℹ️  Note: Resend test domain (onboarding@resend.dev) can only send to your account email.');
    console.log('   For production, verify a domain at https://resend.com/domains\n');

  } catch (error) {
    console.error('❌ Error testing Resend connection:');
    console.error(error);
    
    if (error.code === 'EAUTH') {
      console.error('\n💡 This looks like an authentication error.');
      console.error('   - Verify your Resend API key is correct');
      console.error('   - Make sure you\'re using "resend" as the username');
      console.error('   - Check that your API key is active in Resend dashboard');
    } else if (error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
      console.error('\n💡 This looks like a connection error.');
      console.error('   - Check your internet connection');
      console.error('   - Verify firewall/network settings');
      console.error('   - Try port 587 instead of 465');
    } else {
      console.error('\n💡 Check the error message above for specific details.');
    }
    
    process.exit(1);
  }
}

// Run the test
testResendConnection().catch((error) => {
  console.error('Unexpected error:', error);
  process.exit(1);
});

