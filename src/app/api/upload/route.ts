import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { createNotificationsForEvent } from '../../../../lib/notify';

// POST /api/upload - Upload a file and save metadata to database
export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    const formData = await request.formData();
    const file = formData.get('file') as File;
    const calendarEntryId = formData.get('calendarEntryId') as string;
    const optionNumber = parseInt(formData.get('optionNumber') as string);
    const description = formData.get('description') as string | null;

    if (!file || !calendarEntryId || !optionNumber || (optionNumber < 1 || optionNumber > 3)) {
      return NextResponse.json(
        { error: 'Missing required fields: file, calendarEntryId, optionNumber (1-3)' },
        { status: 400 }
      );
    }

    // Verify calendar entry exists and user has access
    const { data: entry, error: entryError } = await supabaseAdmin
      .from('calendar_entries')
      .select('id, client, date')
      .eq('id', calendarEntryId)
      .single();

    if (entryError || !entry) {
      return NextResponse.json({ error: 'Calendar entry not found' }, { status: 404 });
    }

    // Check user role and access for DESIGNER
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // DESIGNER can only upload to entries for their assigned clients
    if (userData.role === 'DESIGNER') {
      const assignedClients = Array.isArray(userData.assigned_clients)
        ? userData.assigned_clients
        : (typeof userData.assigned_clients === 'string' ? [userData.assigned_clients] : []);

      const entryClient = (entry as any).client;
      if (!assignedClients.includes(entryClient)) {
        // Also check by client name for backward compatibility
        const { data: clientData } = await supabaseAdmin
          .from('clients')
          .select('id, company_name')
          .eq('id', entryClient)
          .single();

        const clientName = clientData?.company_name;
        if (!clientName || !assignedClients.some(id => {
          // Check if any assigned client ID matches the client name
          return id === clientName;
        })) {
          return NextResponse.json({ error: 'You do not have access to edit this post' }, { status: 403 });
        }
      }
    }

    // Upload file to Supabase Storage
    const fileExt = file.name.split('.').pop();
    const fileName = `${calendarEntryId}/${optionNumber}_${Date.now()}.${fileExt}`;
    const filePath = `post-uploads/${fileName}`;

    // Convert File to ArrayBuffer
    const arrayBuffer = await file.arrayBuffer();
    const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
      .from('calendar-media')
      .upload(filePath, arrayBuffer, {
        contentType: file.type,
        upsert: false
      });

    if (uploadError) {
      console.error('Storage upload error:', uploadError);
      return NextResponse.json({ error: 'Failed to upload file' }, { status: 500 });
    }

    // Get URL for the uploaded file
    // If bucket is public, use getPublicUrl; if private, we'll need signed URLs when fetching
    const { data: urlData } = supabaseAdmin.storage
      .from('calendar-media')
      .getPublicUrl(filePath);

    const fileUrl = urlData.publicUrl;

    // Save upload metadata to database
    const { data: uploadRecord, error: dbError } = await supabaseAdmin
      .from('post_uploads')
      .insert([{
        calendar_entry_id: calendarEntryId,
        option_number: optionNumber,
        file_url: fileUrl,
        file_name: file.name,
        file_type: file.type,
        file_size: file.size,
        description: description || null,
        approved: false,
        uploaded_by: currentUser.id
      }])
      .select()
      .single();

    if (dbError) {
      console.error('Database insert error:', dbError);
      // Try to clean up uploaded file
      await supabaseAdmin.storage.from('calendar-media').remove([filePath]);
      return NextResponse.json({ error: 'Failed to save upload metadata' }, { status: 500 });
    }

    // Notify upload event
    try {
      const clientId = (entry as any).client;
      await createNotificationsForEvent({
        type: 'UPLOAD',
        clientId,
        entryId: calendarEntryId,
        actorUserId: currentUser.id,
        title: 'New upload',
        body: `A new upload was added for a post`,
        metadata: { route: `/dashboard?month=${new Date((entry as any).date).toISOString().slice(0,7)}` }
      });
    } catch (e) {
      console.error('Notify upload failed:', e);
    }

    return NextResponse.json({ 
      success: true, 
      upload: {
        id: uploadRecord.id,
        fileUrl,
        fileName: file.name,
        fileType: file.type,
        fileSize: file.size,
        description,
        approved: false,
        optionNumber
      }
    }, { status: 201 });

  } catch (error) {
    console.error('Error in POST /api/upload:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

