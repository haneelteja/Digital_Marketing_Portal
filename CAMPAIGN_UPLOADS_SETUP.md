# Campaign Uploads Setup Guide

## Overview
The Campaign Uploads feature allows users to upload images/videos for social media campaigns, with approval and commenting functionality.

## Prerequisites
1. ✅ Database schema applied (`create_campaign_uploads_table.sql`)
2. ⚠️ **Supabase Storage bucket created** (see Step 2 below)
3. Application code deployed

## Step 1: Database Tables ✅
The SQL migration has been successfully executed. The following tables are created:
- `campaign_uploads` - Stores upload metadata (file URL, approval status, etc.)
- `campaign_upload_comments` - Stores comments on uploads (approval, disapproval, feedback)

## Step 2: Create Supabase Storage Bucket ⚠️ REQUIRED

### In Supabase Dashboard:
1. Navigate to **Storage** → **Buckets**
2. Click **New bucket**
3. Configure:
   - **Name**: `campaign-media` (exact name required)
   - **Public bucket**: ✅ **YES** (recommended for easier access)
   - **File size limit**: Set as needed (default: 50MB per file)
   - **Allowed MIME types**: Leave empty or specify:
     - `image/*` (for images)
     - `video/*` (for videos)

### Alternative: Private Bucket with RLS
If you prefer a private bucket, configure RLS policies:

```sql
-- Allow authenticated users to upload files
CREATE POLICY "Users can upload campaign media"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'campaign-media');

-- Allow authenticated users to view files
CREATE POLICY "Users can view campaign media"
ON storage.objects FOR SELECT
TO authenticated
USING (bucket_id = 'campaign-media');

-- Allow users to update their own uploads (optional)
CREATE POLICY "Users can update campaign media"
ON storage.objects FOR UPDATE
TO authenticated
USING (bucket_id = 'campaign-media');

-- Allow users to delete uploads (optional)
CREATE POLICY "Users can delete campaign media"
ON storage.objects FOR DELETE
TO authenticated
USING (bucket_id = 'campaign-media');
```

## Step 3: Verify Functionality

### Test Checklist:

1. **Campaigns Loading**
   - ✅ Navigate to Social Media Campaigns tab
   - ✅ Verify campaigns are displayed in the table
   - ✅ Click on a campaign to open detail view

2. **File Upload**
   - ✅ Click on a campaign to open detail view
   - ✅ Upload an image/video for Option 1
   - ✅ Upload an image/video for Option 2
   - ✅ Verify preview is shown immediately
   - ✅ Verify file persists after page refresh

3. **Approval Functionality**
   - ✅ As CLIENT user, approve an upload with comment
   - ✅ As IT_ADMIN/AGENCY_ADMIN, approve an upload with comment
   - ✅ Verify approval status is saved
   - ✅ Verify approval comment is displayed

4. **Disapproval Functionality**
   - ✅ Disapprove an upload
   - ✅ Verify disapproval status is saved
   - ✅ Verify disapproval comment is displayed

5. **Comments Functionality**
   - ✅ Add a feedback comment on an upload
   - ✅ Verify comment is saved and displayed
   - ✅ Verify comment shows user name and timestamp

6. **Access Control**
   - ✅ CLIENT users can only see campaigns for their assigned clients
   - ✅ CLIENT users can approve uploads for their assigned clients
   - ✅ IT_ADMIN/AGENCY_ADMIN can see all campaigns
   - ✅ DESIGNER users can upload to assigned campaigns

## API Endpoints

### GET `/api/campaign-uploads?campaignId={id}`
- Fetches all uploads for a campaign
- Returns uploads with comments
- Requires authentication
- Enforces RBAC

### POST `/api/campaign-uploads`
- Uploads a file for a campaign option
- Accepts FormData with:
  - `file`: File object (image or video)
  - `campaignId`: Campaign UUID
  - `optionNumber`: 1 or 2
  - `description`: Optional description
- Returns upload metadata
- Requires authentication
- Enforces RBAC

### PUT `/api/campaign-uploads/[id]`
- Updates upload approval status
- Accepts JSON body:
  - `approved`: boolean
  - `comment`: string (required for approval)
- Returns updated upload with comments
- Requires authentication
- Enforces RBAC (only IT_ADMIN, AGENCY_ADMIN, CLIENT can approve)

### POST `/api/campaign-uploads/[id]/comments`
- Adds a feedback comment to an upload
- Accepts JSON body:
  - `commentText`: string
- Returns new comment with user info
- Requires authentication
- Enforces RBAC

## File Storage Structure

Files are stored in Supabase Storage with the following structure:
```
campaign-media/
  campaign-uploads/
    {campaignId}/
      {optionNumber}_{timestamp}_{filename}
```

Example:
```
campaign-media/
  campaign-uploads/
    abc123-def456-ghi789/
      1_1704067200000_image.jpg
      2_1704067300000_video.mp4
```

## Database Schema

### `campaign_uploads` Table
- `id`: UUID (primary key)
- `campaign_id`: UUID (foreign key to `social_media_campaigns`)
- `option_number`: INTEGER (1 or 2)
- `file_url`: TEXT (Supabase Storage URL)
- `file_name`: TEXT
- `file_type`: TEXT (MIME type)
- `file_size`: BIGINT
- `description`: TEXT (optional)
- `approved`: BOOLEAN (default: false)
- `uploaded_by`: UUID (foreign key to `auth.users`)
- `created_at`: TIMESTAMP
- `updated_at`: TIMESTAMP
- **Unique constraint**: `(campaign_id, option_number)` - only one upload per option

### `campaign_upload_comments` Table
- `id`: UUID (primary key)
- `campaign_upload_id`: UUID (foreign key to `campaign_uploads`)
- `user_id`: UUID (foreign key to `auth.users`)
- `comment_text`: TEXT
- `comment_type`: VARCHAR(20) ('approval', 'disapproval', 'feedback')
- `created_at`: TIMESTAMP

## Troubleshooting

### Issue: "Failed to upload file to storage"
- **Solution**: Ensure the `campaign-media` bucket exists in Supabase Storage
- **Solution**: Check bucket permissions (should be public or have RLS policies)

### Issue: "You do not have access to this campaign"
- **Solution**: Verify user role and assigned clients
- **Solution**: Check RLS policies in database

### Issue: "Upload not found"
- **Solution**: Verify the upload ID exists in `campaign_uploads` table
- **Solution**: Check user has access to the campaign

### Issue: "Approval comment is required"
- **Solution**: When approving, always provide a comment in the approval modal

## Notes

- Each campaign can have up to 2 uploads (one per option)
- Uploading a new file for an option replaces the previous upload
- Old files are automatically deleted from storage when replaced
- Approval status is reset when a new file is uploaded
- Comments are preserved when uploads are replaced
- Only IT_ADMIN, AGENCY_ADMIN, and CLIENT users can approve uploads
- All authenticated users with campaign access can add feedback comments

