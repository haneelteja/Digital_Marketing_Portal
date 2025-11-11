# Monthly Analytics Setup Guide

## Overview
The Monthly Analytics feature allows IT Admins and Agency Admins to upload monthly analytics reports for clients, and allows Clients to view their analytics.

## Prerequisites
1. Database schema applied (see `monthly_analytics_schema.sql`)
2. Supabase Storage bucket created (see below)
3. Application code deployed

## Step 1: Create Database Table
Run the SQL script in your Supabase SQL Editor:

```sql
-- See monthly_analytics_schema.sql for full schema
```

This will:
- Create the `monthly_analytics` table
- Add indexes for performance
- Set up RLS policies for role-based access
- Create triggers for `updated_at` timestamp

## Step 2: Create Supabase Storage Bucket

### In Supabase Dashboard:
1. Navigate to **Storage** → **Buckets**
2. Click **New bucket**
3. Configure:
   - **Name**: `monthly-analytics`
   - **Public bucket**: ✅ **YES** (recommended for easier access)
   - **File size limit**: Set as needed (default: 50MB per file)
   - **Allowed MIME types**: Leave empty or specify allowed types (e.g., `application/pdf,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,image/*,application/zip`)

### Alternative: Private Bucket with RLS
If you prefer a private bucket, configure RLS policies:

```sql
-- Allow authenticated users to upload files
CREATE POLICY "Users can upload monthly analytics"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'monthly-analytics');

-- Allow authenticated users to view files
CREATE POLICY "Users can view monthly analytics"
ON storage.objects FOR SELECT
TO authenticated
USING (bucket_id = 'monthly-analytics');

-- Allow users to update their own uploads
CREATE POLICY "Users can update monthly analytics"
ON storage.objects FOR UPDATE
TO authenticated
USING (bucket_id = 'monthly-analytics');

-- Allow users to delete analytics files (optional)
CREATE POLICY "Users can delete monthly analytics"
ON storage.objects FOR DELETE
TO authenticated
USING (bucket_id = 'monthly-analytics');
```

## Step 3: Verify Setup

### Test Database Table
Run in Supabase SQL Editor:

```sql
-- Check table exists
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name = 'monthly_analytics';

-- Check RLS is enabled
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE tablename = 'monthly_analytics';

-- Check policies
SELECT policyname, cmd 
FROM pg_policies 
WHERE tablename = 'monthly_analytics';
```

### Test Storage Bucket
1. Go to **Storage** → **Buckets** → `monthly-analytics`
2. Verify bucket exists and is accessible
3. Try uploading a test file manually (should work if bucket is public or RLS policies are set)

## Step 4: Test the Feature

### As IT Admin or Agency Admin:
1. Navigate to **Monthly Analytics** tab
2. Select a client (Agency Admins see only assigned clients)
3. Select a month (YYYY-MM format)
4. Select multiple files to upload
5. Click **Upload Analytics**
6. Verify files appear in the table

### As Client:
1. Navigate to **Monthly Analytics** tab
2. View analytics for assigned clients only
3. Filter, sort, and export to Excel as needed
4. Click attachment links to download files

## Features

### Upload (IT Admin & Agency Admin)
- **Multiple file upload**: Select and upload multiple files at once
- **Client selection**: IT Admins see all clients; Agency Admins see only assigned clients
- **Month selection**: Use month picker (YYYY-MM format)
- **File storage**: Files stored in Supabase Storage with organized paths: `{clientId}/{month}/{timestamp}_{filename}`

### View (All Roles)
- **Table display**: 
  - IT Admin & Agency Admin: Client, Month, Attachments, Upload By, Upload Date
  - Client: Month, Attachments, Upload By
- **Filtering**: 
  - By client (IT Admin & Agency Admin only)
  - By month
  - Search by client name, uploader, or filename
- **Sorting**: Click column headers to sort (Month, Client, Upload By, Upload Date)
- **Export**: Export filtered/sorted data to Excel with one click

### Security
- **Role-based access**: 
  - IT Admins can upload for any client
  - Agency Admins can upload only for assigned clients
  - Clients can view only their assigned clients' analytics
- **RLS policies**: Database-level security enforced via Row Level Security
- **File access**: Storage bucket access controlled via RLS (if private) or public access

## File Structure
- Files are stored in Supabase Storage: `monthly-analytics/{clientId}/{month}/{timestamp}_{filename}`
- Metadata stored in database: `monthly_analytics` table
- Attachments stored as JSONB array: `[{filename, url, size, type}, ...]`

## Troubleshooting

### Upload fails with "Failed to upload file"
- Check storage bucket exists: `monthly-analytics`
- Verify bucket permissions (public or RLS policies)
- Check file size limits
- Check browser console for detailed error

### Table shows "No analytics records found"
- Verify database table exists and RLS policies are applied
- Check user has assigned clients (for Agency Admin/Client roles)
- Verify API endpoint is accessible: `/api/monthly-analytics`

### Files not downloading
- Verify storage bucket is public or RLS policies allow SELECT
- Check file URLs in database are correct
- Verify CORS settings in Supabase Storage (if accessing from different domain)

### Permission denied errors
- Verify user role in `users` table
- Check RLS policies match user role
- Ensure `assigned_clients` array contains correct client IDs

## Notes
- Multiple uploads per client per month are allowed (different uploaders or timestamps)
- Files are not automatically deleted; manual cleanup may be needed
- Consider implementing retention policies for old analytics (similar to notifications cleanup)
- Excel export uses `exceljs` library; ensure it's installed: `npm install exceljs`

