# Artwork Uploads Setup Guide

## Overview
The Artwork Uploads feature allows users to upload images/videos for artwork orders, with approval, commenting, and preview functionality.

## Prerequisites
1. ✅ Database schema applied (`create_artwork_uploads_table.sql`)
2. ⚠️ **Supabase Storage bucket** (see options below)

## Storage Bucket Options

### Option 1: Use Existing `campaign-media` Bucket (Current Implementation) ✅

**Pros:**
- No additional setup required
- Already configured and working
- Files are organized in separate folders:
  - `campaign-media/campaign-uploads/` for campaigns
  - `campaign-media/artwork-uploads/` for artworks

**Cons:**
- Mixed content in one bucket
- Shared permissions for both campaigns and artworks

**Status:** ✅ **Currently working** - No action needed if you want to keep using this bucket.

---

### Option 2: Create Dedicated `artwork-media` Bucket (Recommended) ⭐

**Pros:**
- Better organization and separation of concerns
- Independent permissions and RLS policies
- Easier to manage and clean up artwork files separately
- More scalable for future artwork-specific features

**Cons:**
- Requires creating a new bucket
- Requires updating the API code

---

## Step 1: Create Storage Bucket (If using Option 2)

### In Supabase Dashboard:
1. Navigate to **Storage** → **Buckets**
2. Click **New bucket**
3. Configure:
   - **Name**: `artwork-media` (exact name required)
   - **Public bucket**: ✅ **YES** (recommended for easier access)
   - **File size limit**: Set as needed (default: 50MB per file)
   - **Allowed MIME types**: Leave empty or specify:
     - `image/*` (for images)
     - `video/*` (for videos)

### Alternative: Private Bucket with RLS
If you prefer a private bucket, configure RLS policies:

```sql
-- Allow authenticated users to upload artwork files
CREATE POLICY "Users can upload artwork media"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'artwork-media');

-- Allow authenticated users to view artwork files
CREATE POLICY "Users can view artwork media"
ON storage.objects FOR SELECT
TO authenticated
USING (bucket_id = 'artwork-media');

-- Allow users to update their own uploads (optional)
CREATE POLICY "Users can update artwork media"
ON storage.objects FOR UPDATE
TO authenticated
USING (bucket_id = 'artwork-media');

-- Allow users to delete artwork uploads (optional)
CREATE POLICY "Users can delete artwork media"
ON storage.objects FOR DELETE
TO authenticated
USING (bucket_id = 'artwork-media');
```

---

## Step 2: Update API Code (If using Option 2)

If you created a dedicated `artwork-media` bucket, update the API endpoint:

**File:** `src/app/api/artwork-uploads/route.ts`

Replace all instances of:
```typescript
.from('campaign-media')
```

With:
```typescript
.from('artwork-media')
```

**Locations to update:**
- Line ~171: Upload file
- Line ~184: Get public URL
- Line ~203: Delete old file (if exists)
- Line ~226: Cleanup on error
- Line ~251: Cleanup on error

---

## File Storage Structure

### Current (using `campaign-media`):
```
campaign-media/
  campaign-uploads/
    {campaignId}/
      {optionNumber}_{timestamp}_{filename}
  artwork-uploads/
    {artworkId}/
      {optionNumber}_{timestamp}_{filename}
```

### With dedicated bucket (using `artwork-media`):
```
artwork-media/
  artwork-uploads/
    {artworkId}/
      {optionNumber}_{timestamp}_{filename}
```

---

## Verification

### Test Upload Functionality:
1. Navigate to Artworks tab
2. Click on any artwork order
3. Try uploading an image/video to Option 1 or Option 2
4. Verify:
   - ✅ File uploads successfully
   - ✅ Preview appears correctly
   - ✅ Download button works
   - ✅ Zoom/pan functionality works
   - ✅ Comments can be added

### Check Storage:
1. Go to Supabase Dashboard → Storage
2. Navigate to the bucket (`campaign-media` or `artwork-media`)
3. Verify files are being stored in the correct folder structure

---

## Troubleshooting

### Issue: "Failed to upload file to storage"
- **Solution**: Ensure the storage bucket exists in Supabase Storage
- **Solution**: Check bucket permissions (should be public or have RLS policies)
- **Solution**: Verify bucket name matches in API code (`campaign-media` or `artwork-media`)

### Issue: "You do not have access to this artwork"
- **Solution**: Verify user role and assigned clients
- **Solution**: Check RLS policies on `artworks` table

### Issue: Images not displaying
- **Solution**: Check Content Security Policy in `next.config.ts` allows Supabase storage domains
- **Solution**: Verify file URLs are accessible (public bucket or proper RLS policies)

---

## Recommendation

**For production:** I recommend **Option 2** (dedicated `artwork-media` bucket) for better organization and maintainability.

**For quick setup:** **Option 1** (existing `campaign-media` bucket) works fine and requires no changes.

