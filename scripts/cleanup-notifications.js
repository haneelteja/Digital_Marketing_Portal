/**
 * Manual Notifications Cleanup Script
 * Deletes notifications older than 90 days
 * 
 * Usage:
 *   node scripts/cleanup-notifications.js
 * 
 * Environment variables required:
 *   SUPABASE_SERVICE_ROLE_KEY
 *   NEXT_PUBLIC_SUPABASE_URL
 */

const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');

// Load environment variables from .env.local if available
try {
  require('dotenv').config({ path: '.env.local' });
} catch (e) {
  // dotenv not installed, try reading .env.local manually
  try {
    const envPath = path.join(process.cwd(), '.env.local');
    if (fs.existsSync(envPath)) {
      const envContent = fs.readFileSync(envPath, 'utf8');
      envContent.split('\n').forEach(line => {
        const match = line.match(/^([^#=]+)=(.*)$/);
        if (match) {
          const key = match[1].trim();
          const value = match[2].trim().replace(/^["']|["']$/g, '');
          if (!process.env[key]) {
            process.env[key] = value;
          }
        }
      });
    }
  } catch (err) {
    // Ignore errors, rely on process.env
  }
}

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error('❌ Error: Missing required environment variables');
  console.error('   Please ensure .env.local contains:');
  console.error('   - NEXT_PUBLIC_SUPABASE_URL');
  console.error('   - SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

async function cleanupNotifications() {
  try {
    console.log('🔍 Checking for notifications older than 90 days...');
    
    // Calculate cutoff date (90 days ago)
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 90);
    const cutoffISO = cutoffDate.toISOString();

    // Preview what will be deleted
    const { data: preview, error: previewError } = await supabase
      .from('notifications')
      .select('id, created_at', { count: 'exact' })
      .lt('created_at', cutoffISO);

    if (previewError) {
      console.error('❌ Error previewing notifications:', previewError);
      process.exit(1);
    }

    const count = preview?.length || 0;
    
    if (count === 0) {
      console.log('✅ No notifications older than 90 days found. Nothing to clean up.');
      console.log(`   Cutoff date: ${cutoffDate.toISOString().split('T')[0]}`);
      return;
    }

    console.log(`📊 Found ${count} notification(s) to delete`);
    console.log(`   Cutoff date: ${cutoffDate.toISOString().split('T')[0]}`);
    
    if (preview && preview.length > 0) {
      const oldest = new Date(preview[preview.length - 1].created_at);
      const newest = new Date(preview[0].created_at);
      console.log(`   Oldest: ${oldest.toISOString().split('T')[0]}`);
      console.log(`   Newest to delete: ${newest.toISOString().split('T')[0]}`);
    }

    // Confirm deletion
    console.log('\n🗑️  Deleting old notifications...');

    const { data: deleted, error: deleteError } = await supabase
      .from('notifications')
      .delete()
      .lt('created_at', cutoffISO)
      .select('id');

    if (deleteError) {
      console.error('❌ Error deleting notifications:', deleteError);
      process.exit(1);
    }

    const deletedCount = deleted?.length || 0;
    console.log(`✅ Successfully deleted ${deletedCount} notification(s)`);
    
    // Verify
    const { count: remaining } = await supabase
      .from('notifications')
      .select('*', { count: 'exact', head: true })
      .lt('created_at', cutoffISO);

    if (remaining === 0) {
      console.log('✅ Verification: All old notifications have been removed');
    } else {
      console.warn(`⚠️  Warning: ${remaining} old notification(s) still remain`);
    }

  } catch (error) {
    console.error('❌ Unexpected error:', error);
    process.exit(1);
  }
}

// Run cleanup
cleanupNotifications();

