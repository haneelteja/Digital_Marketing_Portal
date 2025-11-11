import { NextRequest } from 'next/server';
import { supabaseAdmin } from '../../../../../lib/supabaseAdmin';
import { unauthorized, serverError, ok } from '../../../../../lib/apiResponse';

// DELETE /api/notifications/cleanup
// Requires admin authentication or secret token
// Can be called by cron jobs, scheduled tasks, etc.
export async function DELETE(request: NextRequest) {
  try {
    // Optional: require secret token for cron jobs
    const secret = request.headers.get('x-cron-secret') || request.headers.get('authorization');
    const expectedSecret = process.env.NOTIFICATIONS_CLEANUP_SECRET || 'default-secret-change-in-production';
    
    if (!secret || (secret !== `Bearer ${expectedSecret}` && secret !== expectedSecret)) {
      return unauthorized('Invalid secret');
    }

    // Delete notifications older than 90 days
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 90);
    const cutoffISO = cutoffDate.toISOString();

    const { data, error } = await supabaseAdmin
      .from('notifications')
      .delete()
      .lt('created_at', cutoffISO)
      .select('id');

    if (error) {
      console.error('Cleanup error:', error);
      return serverError('Failed to clean up notifications');
    }

    const deletedCount = data?.length || 0;
    return ok({ deleted: deletedCount, cutoff: cutoffISO });
  } catch (e) {
    console.error('Cleanup exception:', e);
    return serverError();
  }
}

