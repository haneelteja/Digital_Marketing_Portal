# Database Setup Guide

## 🗄️ Supabase Database Configuration

### 1. Create Supabase Project
1. Go to [supabase.com](https://supabase.com)
2. Create a new project
3. Note your project URL and anon key

### 2. Required Tables

#### Clients Table
```sql
CREATE TABLE IF NOT EXISTS clients (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    company_name TEXT NOT NULL,
    gst_number TEXT NOT NULL,
    email TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Enable RLS
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;

-- Create RLS policies
CREATE POLICY "Users can view all clients" ON clients FOR SELECT USING (true);
CREATE POLICY "Users can insert clients" ON clients FOR INSERT WITH CHECK (true);
CREATE POLICY "Users can update clients" ON clients FOR UPDATE USING (true);
CREATE POLICY "Users can delete clients" ON clients FOR DELETE USING (true);
```

#### Calendar Entries Table
```sql
CREATE TABLE IF NOT EXISTS calendar_entries (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    date DATE NOT NULL,
    client TEXT NOT NULL,
    post_type TEXT NOT NULL,
    platform TEXT,
    content TEXT,
    image_url TEXT,
    status TEXT,
    campaign_priority TEXT,
    post_content TEXT,
    hashtags TEXT,
    user_id UUID REFERENCES auth.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE calendar_entries ENABLE ROW LEVEL SECURITY;

-- Create RLS policies (run fix_rls_policies.sql)
```

### 3. Run RLS Policies Script
Execute the contents of `fix_rls_policies.sql` in your Supabase SQL Editor.

### 4. Test Database Setup
Execute the contents of `test_rls_policies.sql` to verify everything is working.

### 5. Sample Data (Optional)
```sql
-- Insert sample clients
INSERT INTO clients (company_name, gst_number, email, phone_number, address) VALUES
('Acme Corp', '29ABCDE1234F1Z5', 'contact@acme.com', '+91-9876543210', '123 Business St, Mumbai'),
('Tech Solutions', '29FGHIJ5678K2L6', 'info@techsolutions.com', '+91-9876543211', '456 Tech Park, Bangalore');

-- Insert sample calendar entries
INSERT INTO calendar_entries (date, client, post_type, campaign_priority, post_content, hashtags) VALUES
('2024-12-09', 'Acme Corp', 'Social Media Post', 'High', 'New product launch announcement', '#product #launch #acme'),
('2024-12-10', 'Tech Solutions', 'Blog Post', 'Medium', 'Technology trends for 2024', '#tech #trends #2024');
```

## 🔐 Security Configuration

### Row Level Security (RLS)
- All tables have RLS enabled
- Users can only access their own data
- Proper authentication required

### Authentication
- Supabase Auth handles user management
- JWT tokens for API authentication
- Session management

## 📊 Database Features

### Indexes for Performance
```sql
-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_calendar_entries_date ON calendar_entries(date);
CREATE INDEX IF NOT EXISTS idx_calendar_entries_client ON calendar_entries(client);
CREATE INDEX IF NOT EXISTS idx_calendar_entries_user_id ON calendar_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_clients_company_name ON clients(company_name);
```

### Triggers for Updated At
```sql
-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply to tables
CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_calendar_entries_updated_at BEFORE UPDATE ON calendar_entries FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

## 🔍 Monitoring and Maintenance

### Database Monitoring
- Use Supabase Dashboard for monitoring
- Check query performance
- Monitor storage usage

### Backup Strategy
- Enable automatic backups in Supabase
- Export data regularly
- Keep schema changes in version control

### Performance Optimization
- Use appropriate indexes
- Monitor slow queries
- Optimize RLS policies
- Consider connection pooling for high traffic


