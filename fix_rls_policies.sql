-- Fix Row Level Security (RLS) Policies for calendar_entries table
-- Run this script in your Supabase SQL Editor

-- Step 1: Add user_id column if it doesn't exist
ALTER TABLE calendar_entries 
ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id);

-- Step 2: Enable RLS on calendar_entries table
ALTER TABLE calendar_entries ENABLE ROW LEVEL SECURITY;

-- Step 3: Drop existing policies if they exist (to avoid conflicts)
DROP POLICY IF EXISTS "Allow authenticated users to insert calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Allow authenticated users to select calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Allow authenticated users to update calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Allow authenticated users to delete calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Users can insert their own calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Users can select their own calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Users can update their own calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Users can delete their own calendar entries" ON calendar_entries;

-- Step 4: Create new RLS policies

-- Allow authenticated users to insert calendar entries
CREATE POLICY "Allow authenticated users to insert calendar entries" 
ON calendar_entries 
FOR INSERT 
TO authenticated 
WITH CHECK (auth.uid() = user_id);

-- Allow authenticated users to select their own calendar entries
CREATE POLICY "Allow authenticated users to select their own calendar entries" 
ON calendar_entries 
FOR SELECT 
TO authenticated 
USING (auth.uid() = user_id);

-- Allow authenticated users to update their own calendar entries
CREATE POLICY "Allow authenticated users to update their own calendar entries" 
ON calendar_entries 
FOR UPDATE 
TO authenticated 
USING (auth.uid() = user_id) 
WITH CHECK (auth.uid() = user_id);

-- Allow authenticated users to delete their own calendar entries
CREATE POLICY "Allow authenticated users to delete their own calendar entries" 
ON calendar_entries 
FOR DELETE 
TO authenticated 
USING (auth.uid() = user_id);

-- Step 5: Update existing records to have user_id (if any exist)
-- This will set user_id to the first authenticated user for existing records
-- You may want to modify this based on your needs
UPDATE calendar_entries 
SET user_id = (SELECT id FROM auth.users LIMIT 1)
WHERE user_id IS NULL;

-- Step 6: Make user_id NOT NULL (optional, but recommended)
-- ALTER TABLE calendar_entries ALTER COLUMN user_id SET NOT NULL;

-- Step 7: Verify the policies are working
-- You can test this by running:
-- SELECT * FROM calendar_entries; -- Should only show your own entries
-- INSERT INTO calendar_entries (date, client, post_type, campaign_priority, user_id) 
-- VALUES ('2024-01-01', 'Test Client', 'Test Post', 'High', auth.uid());

-- Success message
SELECT 'RLS policies have been successfully created for calendar_entries table' as status;
