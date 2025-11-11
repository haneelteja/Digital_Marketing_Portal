# Save Entry Error - Debug Guide

## 🐛 Issue
When trying to save a manual entry, you get the error: "Error saving entry: {}"

## 🔍 Root Cause Analysis

The empty error object `{}` suggests:
1. **Supabase Connection Issues**: Database connection problems
2. **Data Validation Errors**: Invalid data format being sent
3. **Permission Issues**: RLS policies blocking the insert
4. **Network Issues**: Request failing silently

## 🛠️ Enhanced Error Handling

I've added comprehensive error handling to help identify the exact issue:

### 1. **Supabase Client Validation**
```typescript
// Validate environment variables
if (!supabaseUrl) {
  console.error('Missing NEXT_PUBLIC_SUPABASE_URL environment variable');
  throw new Error('Missing NEXT_PUBLIC_SUPABASE_URL environment variable');
}

if (!supabaseAnonKey) {
  console.error('Missing NEXT_PUBLIC_SUPABASE_ANON_KEY environment variable');
  throw new Error('Missing NEXT_PUBLIC_SUPABASE_ANON_KEY environment variable');
}
```

### 2. **Connection Test Function**
```typescript
async function testSupabaseConnection() {
  try {
    console.log('Testing Supabase client...');
    console.log('Client object:', supabase);
    console.log('Client type:', typeof supabase);
    console.log('Client methods:', Object.getOwnPropertyNames(supabase));
    
    // Try a simple query
    const { data, error } = await supabase
      .from('calendar_entries')
      .select('id')
      .limit(1);
    
    console.log('Test query result:', { data, error });
    return { success: !error, data, error };
  } catch (err) {
    console.error('Supabase test failed:', err);
    return { success: false, error: err };
  }
}
```

### 2. **Data Validation**
```typescript
// Validate data before sending
const entryData = {
  date: date.trim(),
  client: (client || 'Default Client').trim(),
  post_type: postType.trim(),
  post_content: postContent?.trim() || null,
  hashtags: hashtags?.trim() || null,
  campaign_priority: priority
};
```

### 3. **Detailed Error Logging**
```typescript
console.error('Error details:', {
  message: err instanceof Error ? err.message : 'Unknown error',
  stack: err instanceof Error ? err.stack : undefined,
  type: typeof err,
  constructor: err?.constructor?.name,
  keys: err && typeof err === 'object' ? Object.keys(err) : [],
  fullError: JSON.stringify(err, null, 2)
});
```

### 4. **Enhanced Supabase Error Details**
```typescript
console.error('Supabase error details:', {
  code: error.code,
  message: error.message,
  details: error.details,
  hint: error.hint,
  fullError: error,
  errorType: typeof error,
  errorKeys: Object.keys(error),
  errorString: String(error),
  errorJSON: JSON.stringify(error, null, 2)
});

// Handle different types of errors
if (error.code) {
  throw new Error(`Database error: ${error.message} (${error.code})`);
} else if (error.message) {
  throw new Error(`Database error: ${error.message}`);
} else {
  throw new Error(`Unknown database error: ${JSON.stringify(error)}`);
}
```

### 5. **Comprehensive Error Extraction**
```typescript
// Try to extract meaningful error message
let errorMessage = 'Failed to save entry. Please try again.';

if (err instanceof Error) {
  errorMessage = err.message;
} else if (typeof err === 'string') {
  errorMessage = err;
} else if (err && typeof err === 'object') {
  // Try to extract message from object
  if ('message' in err && typeof err.message === 'string') {
    errorMessage = err.message;
  } else if ('error' in err && typeof err.error === 'string') {
    errorMessage = err.error;
  } else {
    errorMessage = `Unknown error: ${JSON.stringify(err)}`;
  }
}
```

## 🧪 Testing the Fix

### Step 1: Try Saving an Entry
1. Go to "Add to Calendar" → "Manual Entry"
2. Fill in the required fields:
   - Date (select from calendar)
   - Post Type
   - Priority
3. Click "Save"
4. Check browser console for detailed logs

### Step 2: Check Console Output

#### Successful Save:
```
Submitting manual entry with date: 2024-01-15
Date as Date object: [Date object]
Testing Supabase connection...
Supabase connection test passed
Validated entry data: { date: "2024-01-15", client: "Default Client", ... }
Successfully saved entry: [...]
```

#### Connection Error:
```
Testing Supabase connection...
Supabase connection test failed: { code: "PGRST301", message: "permission denied" }
Database connection failed: permission denied
```

#### Data Validation Error:
```
Missing required fields: date, post_type, or campaign_priority
```

#### Supabase Insert Error:
```
Supabase error details: { code: "23505", message: "duplicate key value", ... }
Database error: duplicate key value (23505)
```

## 🚨 Troubleshooting

### If Connection Test Fails:

1. **Check Supabase Configuration**:
   - Verify `NEXT_PUBLIC_SUPABASE_URL` in `.env.local`
   - Verify `NEXT_PUBLIC_SUPABASE_ANON_KEY` in `.env.local`

2. **Check Database Access**:
   - Go to Supabase Dashboard → Database → Tables
   - Verify `calendar_entries` table exists
   - Check if you can see the table data

3. **Check RLS Policies**:
   - Go to Database → Policies
   - Look for `calendar_entries` table policies
   - Ensure INSERT policy allows your user

### If Data Validation Fails:

1. **Check Required Fields**:
   - Ensure date is selected
   - Ensure post type is filled
   - Ensure priority is selected

2. **Check Data Format**:
   - Date should be in YYYY-MM-DD format
   - All text fields should be trimmed
   - No empty strings for required fields

### If Supabase Insert Fails:

1. **Check Error Code**:
   - `23505`: Duplicate key (entry already exists)
   - `23503`: Foreign key violation
   - `23502`: Not null violation
   - `PGRST301`: Permission denied

2. **Check Table Schema**:
   - Verify all required columns exist
   - Check data types match
   - Ensure no constraint violations

## 📊 Expected Console Output

### Successful Save:
```
Submitting manual entry with date: 2024-01-15
Date as Date object: Mon Jan 15 2024 00:00:00 GMT+0000
Testing Supabase connection...
Supabase connection test passed
Validated entry data: {
  "date": "2024-01-15",
  "client": "Default Client",
  "post_type": "Social Media",
  "post_content": "Sample post",
  "hashtags": "#test #sample",
  "campaign_priority": "Medium"
}
Successfully saved entry: [{"id": "abc123", "date": "2024-01-15", ...}]
```

### Common Error Scenarios:

#### Permission Denied:
```
Testing Supabase connection...
Supabase connection test failed: {
  "code": "PGRST301",
  "message": "permission denied for table calendar_entries"
}
Database connection failed: permission denied for table calendar_entries
```

#### Missing Required Field:
```
Missing required fields: date, post_type, or campaign_priority
```

#### Duplicate Entry:
```
Supabase error details: {
  "code": "23505",
  "message": "duplicate key value violates unique constraint",
  "details": "Key (date, client)=(2024-01-15, Default Client) already exists."
}
Database error: duplicate key value violates unique constraint (23505)
```

## 🎯 Next Steps

1. **Test the enhanced error handling** by trying to save an entry
2. **Check console logs** for detailed error information
3. **Fix any identified issues** based on the error details
4. **Verify Supabase configuration** if connection fails
5. **Check RLS policies** if permission errors occur

The enhanced error handling should now provide clear information about what's causing the save failure!
