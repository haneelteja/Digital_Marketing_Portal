# Image Upload Persistence Setup

## Problem
Images uploaded to posts were only stored in client-side state and were not visible to other users. This was because:
- Files were stored only in browser memory as FileReader data URLs
- No database persistence
- No Supabase Storage integration

## Solution Implemented

### 1. Database Table Created
- **Table**: `post_uploads`
- **Schema**: `create_uploads_table.sql`
- Stores upload metadata linking images/videos to calendar entries and options (1, 2, 3)

### 2. API Endpoints Created
- **POST `/api/upload`**: Uploads files to Supabase Storage and saves metadata to database
- **GET `/api/upload/[entryId]`**: Retrieves all uploads for a calendar entry

### 3. Code Changes
- Modified `handleConfirmUploadWithComment` to upload files to storage and database
- Added `storedUploads` state to hold uploads from database
- Updated display logic to show database uploads (visible to all users) instead of just client state
- Added automatic upload loading when displaying post details

## Setup Instructions

### Step 1: Create Database Table
Run the SQL script in your Supabase SQL Editor:
```sql
-- See create_uploads_table.sql for the full schema
```

### Step 2: Create Storage Bucket
1. Go to Supabase Dashboard → Storage
2. Create a new bucket named `calendar-media`
3. Set bucket to **Public** (or configure RLS policies for authenticated users)

### Step 3: Configure Storage Policies (if bucket is not public)
If you want to keep the bucket private, add these RLS policies:

```sql
-- Allow authenticated users to upload files
CREATE POLICY "Users can upload files"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'calendar-media');

-- Allow authenticated users to view files
CREATE POLICY "Users can view files"
ON storage.objects FOR SELECT
TO authenticated
USING (bucket_id = 'calendar-media');

-- Allow users to update their own uploads (optional)
CREATE POLICY "Users can update own uploads"
ON storage.objects FOR UPDATE
TO authenticated
USING (bucket_id = 'calendar-media');

-- Allow users to delete uploads (optional)
CREATE POLICY "Users can delete uploads"
ON storage.objects FOR DELETE
TO authenticated
USING (bucket_id = 'calendar-media');
```

### Step 4: Test the Setup
1. Upload an image to a post (Option 1, 2, or 3)
2. Refresh the page - the image should still be visible
3. Log in as a different user - they should see the uploaded image
4. Verify the image URL in the database points to Supabase Storage

## How It Works Now

1. **Upload Flow**:
   - User selects a file
   - File is temporarily stored in client state (for preview)
   - When confirmed with comment, file is uploaded to `/api/upload`
   - API uploads file to Supabase Storage bucket `calendar-media`
   - API saves metadata (URL, filename, type, etc.) to `post_uploads` table
   - Client state is updated with the storage URL

2. **Display Flow**:
   - When post details are viewed, uploads are loaded from database via `/api/upload/[entryId]`
   - Display logic checks `storedUploads` first (database), then falls back to client state
   - All users see the same images from database storage

3. **Benefits**:
   - ✅ Images persist across sessions
   - ✅ All users can see uploaded images
   - ✅ Images are withered in Supabase Storage (scalable)
   - ✅ Metadata stored in database for querying

## Notes

- The `calendar-media` storage bucket must exist before uploading files
- If the bucket is private, ensure RLS policies allow authenticated users to read files
- File paths in storage follow the pattern: `post-uploads/{calendarEntryId}/{optionNumber}_{timestamp}.{ext}`
- Each calendar entry can have up to 3 uploads (one per option)



