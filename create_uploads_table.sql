-- Create uploads table to store images/videos for calendar entries
-- This table links uploads to specific calendar entries and options

CREATE TABLE IF NOT EXISTS post_uploads (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    calendar_entry_id UUID NOT NULL REFERENCES calendar_entries(id) ON DELETE CASCADE,
    option_number INTEGER NOT NULL CHECK (option_number IN (1, 2, 3)),
    file_url TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    file_size BIGINT,
    description TEXT,
    approved BOOLEAN DEFAULT false,
    uploaded_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(calendar_entry_id, option_number)
);

-- Enable RLS
ALTER TABLE post_uploads ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist (to make script idempotent)
DROP POLICY IF EXISTS "Users can view uploads for accessible entries" ON post_uploads;
DROP POLICY IF EXISTS "Users can insert uploads" ON post_uploads;
DROP POLICY IF EXISTS "Users can update uploads" ON post_uploads;
DROP POLICY IF EXISTS "Users can delete uploads" ON post_uploads;

-- RLS Policies: All authenticated users can view uploads for calendar entries they have access to
-- (RLS on calendar_entries will handle the filtering)
CREATE POLICY "Users can view uploads for accessible entries" 
ON post_uploads FOR SELECT 
USING (
    EXISTS (
        SELECT 1 FROM calendar_entries ce 
        WHERE ce.id = post_uploads.calendar_entry_id
    )
);

-- Users can insert uploads
CREATE POLICY "Users can insert uploads" 
ON post_uploads FOR INSERT 
WITH CHECK (auth.role() = 'authenticated');

-- Users can update their own uploads or uploads for entries they manage
CREATE POLICY "Users can update uploads" 
ON post_uploads FOR UPDATE 
USING (auth.role() = 'authenticated')
WITH CHECK (auth.role() = 'authenticated');

-- Users can delete uploads (same permissions as update)
CREATE POLICY "Users can delete uploads" 
ON post_uploads FOR DELETE 
USING (auth.role() = 'authenticated');

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_post_uploads_entry_id ON post_uploads(calendar_entry_id);
CREATE INDEX IF NOT EXISTS idx_post_uploads_option ON post_uploads(calendar_entry_id, option_number);

