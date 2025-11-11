# 🚀 Quick Start Guide

## Prerequisites
- Node.js 18+ installed
- Git installed
- Supabase account

## 1. Clone and Setup (5 minutes)

```bash
# Clone the repository
git clone <your-repo-url>
cd Digital_Marketing_Portal_Backup_2025-09-26_21-31-42

# Run automated setup
npm run setup
```

## 2. Configure Environment (2 minutes)

```bash
# Edit environment file
nano .env.local

# Add your Supabase credentials:
NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
```

## 3. Setup Database (3 minutes)

1. Go to [supabase.com](https://supabase.com)
2. Create a new project
3. Copy your project URL and anon key to `.env.local`
4. In Supabase SQL Editor, run:
   - `fix_rls_policies.sql` (for security)
   - `test_rls_policies.sql` (to verify setup)

## 4. Start Application (1 minute)

```bash
# Start development server
npm run start:dev

# Or manually:
npm run dev
```

Visit: `http://localhost:3000`

## 🎯 That's it! Your Digital Marketing Portal is ready.

### Next Steps:
- Add your first client in the Configurations tab
- Create calendar entries for your marketing campaigns
- Export reports and analytics

### Need Help?
- Check `DEPLOYMENT.md` for detailed instructions
- Review `DATABASE_SETUP.md` for database configuration
- Run `npm run health` to check application status

## 🔧 Useful Commands

```bash
# Development
npm run dev              # Start dev server
npm run build           # Build for production
npm run start           # Start production server

# Code Quality
npm run lint            # Check code quality
npm run lint:fix        # Fix linting issues
npm run type-check      # Check TypeScript

# Docker (Optional)
npm run docker:build    # Build Docker image
npm run docker:run      # Run with Docker
npm run docker:compose  # Run with Docker Compose

# Health & Security
npm run health          # Check application health
npm run audit           # Security audit
npm run audit:fix       # Fix security issues
```

## 🚨 Troubleshooting

### Common Issues:
1. **"Supabase connection failed"**
   - Check your `.env.local` file
   - Verify Supabase URL and keys

2. **"Database error"**
   - Run the SQL scripts in Supabase
   - Check RLS policies are enabled

3. **"Build failed"**
   - Run `npm run lint` to check for issues
   - Ensure all dependencies are installed

### Get Help:
- Check browser console for errors
- Review Supabase dashboard
- Run `npm run health` for status check


