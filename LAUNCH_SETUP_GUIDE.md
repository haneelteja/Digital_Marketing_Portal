# Application Launch Setup Guide

## ✅ Application Status

The development server is starting! The application should be available at:
**http://localhost:3000**

---

## ⚠️ IMPORTANT: Configure Your Supabase Credentials

Before the application can fully function, you need to:

### 1. Get Your Supabase Credentials

1. Go to [https://app.supabase.com](https://app.supabase.com)
2. Select your project (or create a new one)
3. Navigate to **Settings** → **API**
4. Copy the following values:
   - **Project URL** → `NEXT_PUBLIC_SUPABASE_URL`
   - **anon/public key** → `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - **service_role key** → `SUPABASE_SERVICE_ROLE_KEY` (keep this secret!)

### 2. Update `.env.local` File

Open `.env.local` in the project root and replace the placeholder values:

```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_actual_anon_key_here
SUPABASE_SERVICE_ROLE_KEY=your_actual_service_role_key_here
```

### 3. Set Up Database Schema

Run the database migration script in your Supabase SQL Editor:

1. Go to Supabase Dashboard → **SQL Editor**
2. Open the file: `supabase_migration.sql`
3. Copy and paste the entire SQL script
4. Click **Run** to execute

This will create all required tables, indexes, and RLS policies.

---

## 🚀 Starting the Application

### Option 1: Using npm (Current)
```bash
npm run dev
```

### Option 2: Using the setup script
```bash
npm run setup
npm run start:dev
```

The application will be available at: **http://localhost:3000**

---

## 📋 Pre-Launch Checklist

- [ ] Supabase project created
- [ ] `.env.local` file created with actual credentials
- [ ] Database migration script executed (`supabase_migration.sql`)
- [ ] Dependencies installed (`npm install`)
- [ ] Development server running (`npm run dev`)

---

## 🔍 Verifying the Setup

### 1. Check Health Endpoint
Visit: http://localhost:3000/api/health

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "...",
  "database": "connected",
  "version": "1.0.0"
}
```

### 2. Check Application
Visit: http://localhost:3000

You should see the login page or be redirected to the dashboard.

---

## 🐛 Troubleshooting

### Issue: "Missing NEXT_PUBLIC_SUPABASE_URL"
**Solution:** Make sure `.env.local` exists and contains your Supabase credentials.

### Issue: "Database connection failed"
**Solution:** 
1. Verify your Supabase credentials are correct
2. Check that the database migration script has been run
3. Verify your Supabase project is active

### Issue: "Port 3000 already in use"
**Solution:** 
```bash
# Kill the process using port 3000 (Windows)
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# Or use a different port
PORT=3001 npm run dev
```

### Issue: "Module not found"
**Solution:** 
```bash
npm install
```

---

## 📚 Next Steps

1. **Create Admin User:**
   - Use the SQL script `create_admin_user.sql` in Supabase SQL Editor
   - Or create a user through the application (if IT_ADMIN role exists)

2. **Configure Email (Optional):**
   - Add SMTP settings to `.env.local` for email notifications
   - See `EMAIL_SETUP_GUIDE.md` for detailed instructions

3. **Test Features:**
   - Login with admin credentials
   - Create a test client
   - Add calendar entries
   - Test file uploads

---

## 📖 Additional Documentation

- **Database Setup:** See `DATABASE_SETUP.md`
- **Deployment:** See `DEPLOYMENT.md`
- **Quick Start:** See `QUICK_START.md`
- **Validation Report:** See `COMPREHENSIVE_VALIDATION_REPORT_2025.md`

---

## 🎯 Application Features

Once configured, you'll have access to:

- ✅ **Dashboard** - Calendar view with post management
- ✅ **Client Management** - CRUD operations with Excel import/export
- ✅ **User Management** - Role-based access control (IT_ADMIN only)
- ✅ **File Uploads** - Multi-option uploads with approval workflow
- ✅ **Monthly Analytics** - Analytics file management
- ✅ **Artworks Management** - Comprehensive artwork tracking
- ✅ **Social Media Campaigns** - Campaign management
- ✅ **Reports** - Statistics and exports (Excel/PDF)
- ✅ **Notifications** - Real-time notifications

---

**Need Help?** Check the documentation files in the project root or review the validation report for detailed information about all features.

