-- User Management Database Schema
-- This file contains the SQL schema for the user management system

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('IT_ADMIN', 'AGENCY_ADMIN', 'CLIENT')),
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    assigned_clients TEXT[], -- Array of client IDs for Agency Admins
    client_id VARCHAR(255), -- Client ID for Client users
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Activity logs table
CREATE TABLE IF NOT EXISTS activity_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT
);

-- Clients table (if not already exists)
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_name VARCHAR(255) NOT NULL,
    gst_number VARCHAR(50),
    email VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20),
    address TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_client_id ON users(client_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_logs_action ON activity_logs(action);

-- Row Level Security (RLS) Policies

-- Enable RLS on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- IT Admins can see all users
CREATE POLICY "IT Admins can view all users" ON users
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = auth.uid() 
            AND u.role = 'IT_ADMIN'
        )
    );

-- Agency Admins can see users associated with their assigned clients
CREATE POLICY "Agency Admins can view assigned client users" ON users
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = auth.uid() 
            AND u.role = 'AGENCY_ADMIN'
            AND (
                users.client_id = ANY(u.assigned_clients)
                OR users.id = u.id
            )
        )
    );

-- Clients can only see themselves
CREATE POLICY "Clients can view themselves" ON users
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = auth.uid() 
            AND u.role = 'CLIENT'
            AND users.id = u.id
        )
    );

-- IT Admins can insert users
CREATE POLICY "IT Admins can create users" ON users
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = auth.uid() 
            AND u.role = 'IT_ADMIN'
        )
    );

-- IT Admins can update all users, users can update themselves (limited fields)
CREATE POLICY "IT Admins can update all users" ON users
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = auth.uid() 
            AND u.role = 'IT_ADMIN'
        )
    );

CREATE POLICY "Users can update themselves" ON users
    FOR UPDATE USING (
        id = auth.uid()
    );

-- IT Admins can delete users (except themselves)
CREATE POLICY "IT Admins can delete users" ON users
    FOR DELETE USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = auth.uid() 
            AND u.role = 'IT_ADMIN'
        )
        AND id != auth.uid()
    );

-- Enable RLS on activity_logs table
ALTER TABLE activity_logs ENABLE ROW LEVEL SECURITY;

-- IT Admins can view all activity logs
CREATE POLICY "IT Admins can view all activity logs" ON activity_logs
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = auth.uid() 
            AND u.role = 'IT_ADMIN'
        )
    );

-- Users can view their own activity logs
CREATE POLICY "Users can view their own activity logs" ON activity_logs
    FOR SELECT USING (
        user_id = auth.uid()
    );

-- Users can insert activity logs
CREATE POLICY "Users can create activity logs" ON activity_logs
    FOR INSERT WITH CHECK (
        user_id = auth.uid()
    );

-- Functions for updating timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updating timestamps
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clients_updated_at 
    BEFORE UPDATE ON clients 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Sample data for testing
INSERT INTO users (id, email, first_name, last_name, role, is_active, email_verified) VALUES
    ('00000000-0000-0000-0000-000000000001', 'admin@example.com', 'IT', 'Administrator', 'IT_ADMIN', true, true),
    ('00000000-0000-0000-0000-000000000002', 'agency@example.com', 'Agency', 'Admin', 'AGENCY_ADMIN', true, true),
    ('00000000-0000-0000-0000-000000000003', 'client@example.com', 'Client', 'User', 'CLIENT', true, true)
ON CONFLICT (email) DO NOTHING;

-- Sample clients
INSERT INTO clients (company_name, gst_number, email, phone_number, address) VALUES
    ('Sample Client 1', 'GST001', 'contact@client1.com', '+1234567890', '123 Main St, City, State'),
    ('Sample Client 2', 'GST002', 'contact@client2.com', '+0987654321', '456 Oak Ave, City, State')
ON CONFLICT DO NOTHING;
