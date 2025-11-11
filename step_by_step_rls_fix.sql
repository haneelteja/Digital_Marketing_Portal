-- Step-by-Step RLS Fix for calendar_entries table
-- Run each step in Supabase SQL Editor one by one

-- STEP 1: Add user_id column to calendar_entries table
ALTER TABLE calendar_entries 
ADD COLUMN user_id UUID REFERENCES auth.users(id);

-- STEP 2: Enable Row Level Security on the table
ALTER TABLE calendar_entries ENABLE ROW LEVEL SECURITY;

-- STEP 3: Create RLS policies

-- Policy 1: Allow authenticated users to insert their own entries
CREATE POLICY "Users can insert their own calendar entries" 
ON calendar_entries 
FOR INSERT 
TO authenticated 
WITH CHECK (auth.uid() = user_id);

-- Policy 2: Allow authenticated users to select their own entries
CREATE POLICY "Users can select their own calendar entries" 
ON calendar_entries 
FOR SELECT 
TO authenticated 
USING (auth.uid() = user_id);

-- Policy 3: Allow authenticated users to update their own entries
CREATE POLICY "Users can update their own calendar entries" 
ON calendar_entries 
FOR UPDATE 
TO authenticated 
USING (auth.uid() = user_id) 
WITH CHECK (auth.uid() = user_id);

-- Policy 4: Allow authenticated users to delete their own entries
CREATE POLICY "Users can delete their own calendar entries" 
ON calendar_entries 
FOR DELETE 
TO authenticated 
USING (auth.uid() = user_id);

-- STEP 4: Update existing records (if any) with a default user_id
-- This will set user_id to the first authenticated user for existing records
UPDATE calendar_entries 
SET user_id = (SELECT id FROM auth.users LIMIT 1)
WHERE user_id IS NULL;

-- STEP 5: Verify the column was added
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'calendar_entries' 
AND column_name = 'user_id';

-- STEP 6: Verify RLS is enabled
SELECT schemaname, tablename, rowsecurity 
FROM pg_tables 
WHERE tablename = 'calendar_entries';

-- STEP 7: Verify policies were created
SELECT policyname, cmd, roles 
FROM pg_policies 
WHERE tablename = 'calendar_entries';

-- Success message
SELECT 'RLS fix completed successfully! The user_id column has been added and policies are created.' as status;
