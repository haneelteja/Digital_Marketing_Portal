# Migration Guide: Convert Calendar Entries Client Names to UUIDs

This migration converts existing calendar entries that have company names stored in the `client` field to use client UUIDs instead.

## ⚠️ Important Note

The Step 1 query shows **duplicate matches** because there are multiple clients with the same company name (e.g., multiple "Benguluru Bhavan" entries). The migration script will automatically pick the **first client ID** (alphabetically) when multiple matches exist for consistency.

## Prerequisites

1. **Backup your database** (Recommended)
   - Go to Supabase Dashboard > Database > Backups
   - Create a manual backup before running the migration

2. **Review current data**
   - Run the verification queries in the migration SQL file to see what needs updating

## Migration Steps

### Step 1: Review Current State ✅ (Already Done)

You've already run Step 1 and found entries that need updating. The results show some entries have multiple matching clients with the same name.

### Step 2: Run the Migration

**Important**: Run this in Supabase SQL Editor using the service role key or as a database admin.

This script will:
- Update entries where client matches a company name (case-insensitive)
- When multiple clients share the same company name, it picks the first one (by ID) for consistency
- Only updates entries that are NOT already UUIDs
- Only updates if a matching client exists

```sql
-- Update entries where client matches a company name (case-insensitive)
-- When multiple clients have the same name, we pick the first one (by ID) for consistency
UPDATE calendar_entries ce
SET 
    client = (
        SELECT c.id::text
        FROM clients c
        WHERE 
            LOWER(TRIM(ce.client)) = LOWER(TRIM(c.company_name))
            AND c.deleted_at IS NULL
        ORDER BY c.id
        LIMIT 1
    )
WHERE 
    -- Only update entries where client is NOT already a UUID
    ce.client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    -- Only update if a matching client exists
    AND EXISTS (
        SELECT 1 
        FROM clients c 
        WHERE LOWER(TRIM(ce.client)) = LOWER(TRIM(c.company_name))
        AND c.deleted_at IS NULL
    );
```

### Step 3: Verify the Migration

Check how many entries were successfully updated:

```sql
SELECT 
    COUNT(*) as total_entries,
    COUNT(CASE 
        WHEN client ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' 
        THEN 1 
    END) as entries_with_uuid,
    COUNT(CASE 
        WHEN client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' 
        THEN 1 
    END) as entries_still_with_names
FROM calendar_entries;
```

**Expected Result**: `entries_still_with_names` should be 0 or 1 (only "RLS Test Client" which has no match).

### Step 4: Handle Unmatched Entries (if any)

If some entries couldn't be matched, find them:

```sql
SELECT 
    ce.id,
    ce.date,
    ce.client as unmatched_company_name,
    ce.post_type,
    ce.created_at
FROM calendar_entries ce
WHERE 
    -- Not a UUID
    ce.client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    -- No matching client found
    AND NOT EXISTS (
        SELECT 1 
        FROM clients c 
        WHERE LOWER(TRIM(ce.client)) = LOWER(TRIM(c.company_name))
        AND c.deleted_at IS NULL
    )
ORDER BY ce.created_at DESC;
```

**Options for unmatched entries:**

1. **Create missing clients** (if the company names are valid)
   - Go to the portal and create the missing clients
   - Re-run the migration Step 2

2. **Delete unmatched entries** (if they're invalid/test data)
   ```sql
   DELETE FROM calendar_entries 
   WHERE client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND NOT EXISTS (
       SELECT 1 FROM clients c 
       WHERE LOWER(TRIM(calendar_entries.client)) = LOWER(TRIM(c.company_name))
       AND c.deleted_at IS NULL
   );
   ```

3. **Manually update** specific entries if needed

### Step 5: Final Verification

Verify that all entries now have UUIDs and can be linked to clients:

```sql
SELECT 
    ce.id,
    ce.date,
    ce.client as client_uuid,
    c.company_name,
    ce.post_type,
    ce.created_at
FROM calendar_entries ce
LEFT JOIN clients c ON ce.client = c.id::text
WHERE ce.client ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
ORDER BY ce.created_at DESC
LIMIT 20;
```

**Expected**: All rows should show `client_uuid` matching a client ID and `company_name` populated.

## Handling Duplicate Company Names

If multiple clients have the same company name (like "Benguluru Bhavan"):
- The migration will automatically select the **first client ID** (alphabetically) for consistency
- If you need to assign specific entries to specific client IDs, you can manually update them after the migration:
  ```sql
  -- Example: Update a specific entry to use a specific client UUID
  UPDATE calendar_entries 
  SET client = 'cd91b78b-8861-4435-a3af-8d61a53769ac' -- Replace with desired client UUID
  WHERE id = '8bd790cb-96f9-4614-af8d-2e47cfc1248b'; -- Replace with calendar entry ID
  ```

## Troubleshooting

### If migration fails:

1. **Check if you're using admin/service role**: The migration needs admin privileges
2. **Verify clients table exists**: Run `SELECT * FROM clients LIMIT 5;`
3. **Check RLS policies**: Temporary disable RLS if needed for migration:
   ```sql
   ALTER TABLE calendar_entries DISABLE ROW LEVEL SECURITY;
   -- Run migration
   ALTER TABLE calendar_entries ENABLE ROW LEVEL SECURITY;
   ```

### After Migration:

1. ✅ All new posts will automatically use UUIDs
2. ✅ Calendar filtering will work correctly for all roles
3. ✅ Posts will be visible to the right users based on client associations

## Rollback (if needed)

If you created a backup table, you can restore:

```sql
-- Only if you created calendar_entries_backup earlier
TRUNCATE calendar_entries;
INSERT INTO calendar_entries SELECT * FROM calendar_entries_backup;
```

