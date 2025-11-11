# Digital Marketing Portal - Deployment Guide

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- npm or yarn
- Supabase account
- Git

### 1. Clone and Install
```bash
git clone <your-repo-url>
cd Digital_Marketing_Portal_Backup_2025-09-26_21-31-42
npm install
```

### 2. Environment Setup
```bash
# Copy environment template
cp env.example .env.local

# Edit .env.local with your Supabase credentials
nano .env.local
```

### 3. Supabase Setup
1. Create a new Supabase project at [supabase.com](https://supabase.com)
2. Get your project URL and anon key from Settings > API
3. Update `.env.local` with your credentials

### 4. Database Setup
Run the SQL scripts in your Supabase SQL Editor:

```sql
-- 1. Create tables (if not exists)
-- 2. Run RLS policies: fix_rls_policies.sql
-- 3. Test policies: test_rls_policies.sql
```

### 5. Start Development Server
```bash
npm run dev
```

Visit `http://localhost:3000`

## 🏗️ Production Deployment

### Vercel Deployment (Recommended)
1. Connect your GitHub repository to Vercel
2. Add environment variables in Vercel dashboard
3. Deploy automatically on push to main branch

### Manual Deployment
```bash
# Build for production
npm run build

# Start production server
npm start
```

### Environment Variables for Production
```bash
NEXT_PUBLIC_SUPABASE_URL=your_production_supabase_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_production_anon_key
NEXT_PUBLIC_APP_URL=https://your-domain.com
NODE_ENV=production
```

## 🗄️ Database Schema

### Required Tables
- `clients` - Client information
- `calendar_entries` - Marketing calendar entries
- `users` - User authentication (handled by Supabase Auth)

### RLS Policies
- Row Level Security enabled
- Users can only access their own data
- Proper authentication required

## 🔧 Configuration

### Next.js Configuration
- TypeScript enabled
- ESLint configured
- Tailwind CSS for styling
- App Router structure

### Security Features
- Row Level Security (RLS)
- Input validation
- Secure file uploads
- XSS protection

## 📊 Features

### Core Functionality
- Marketing calendar
- Client management
- File upload/processing
- Excel import/export
- PDF generation
- Reports and analytics

### Performance
- Virtualized lists for large datasets
- Optimized database queries
- Client-side caching
- Responsive design

## 🚨 Troubleshooting

### Common Issues

1. **Supabase Connection Error**
   - Check environment variables
   - Verify Supabase URL and keys
   - Ensure RLS policies are set up

2. **Build Errors**
   - Run `npm run lint` to check for issues
   - Ensure all dependencies are installed
   - Check TypeScript compilation

3. **Database Errors**
   - Verify table structure
   - Check RLS policies
   - Test with SQL scripts provided

### Support
- Check logs in browser console
- Verify Supabase dashboard
- Review Next.js build output

## 🔄 Updates and Maintenance

### Regular Tasks
- Update dependencies: `npm update`
- Run security audit: `npm audit`
- Check for TypeScript errors: `npm run build`
- Test functionality after updates

### Backup
- Export Supabase data regularly
- Keep environment variables secure
- Version control all changes


