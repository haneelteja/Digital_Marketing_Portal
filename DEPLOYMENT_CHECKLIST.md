# Digital Marketing Portal - Deployment Checklist

## Pre-Deployment Verification

- [ ] ZIP file: `Digital_Marketing_Portal_V2.zip` extracted
- [ ] All files present: `package.json`, `next.config.ts`, `.env.local`, `src/`, `lib/`, `public/`, `scripts/`
- [ ] Production build completed: `.next/` directory exists
- [ ] Node.js version: v18.x or v20.x installed on server

## Environment Configuration

### 1. Extract Archive
```bash
# Extract ZIP to deployment directory
unzip Digital_Marketing_Portal_V2.zip -d /path/to/deployment
cd /path/to/deployment
```

### 2. Environment Variables
Create/verify `.env.local` with required variables:

```env
# Supabase Configuration
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_anon_key_here
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here

# Optional: Node Environment
NODE_ENV=production

# Optional: Port Configuration (if not using default 3000)
PORT=3000

# Optional: Notifications Cleanup Secret (for automated retention)
# Generate a strong random string, e.g., openssl rand -hex 32
NOTIFICATIONS_CLEANUP_SECRET=your-secret-here
```

⚠️ **Security Note**: Never commit `.env.local` to version control. Keep it secure.

### 3. Database Setup
- [ ] Follow `SUPABASE_MIGRATION_GUIDE.docx` to set up database schema
- [ ] Verify all tables created: `users`, `clients`, `calendar_entries`, `activity_logs`, `notifications`
- [ ] RLS policies applied (including notifications)
- [ ] Test database connection

### 4. Notifications Retention (Optional)
Set up automated cleanup of notifications older than 90 days:

**Option A: Using pg_cron (Supabase Pro plan or self-hosted)**
- [ ] Enable pg_cron extension in Supabase SQL editor
- [ ] Run `notifications_retention.sql` to schedule weekly cleanup

**Option B: External cron job**
- [ ] Add `NOTIFICATIONS_CLEANUP_SECRET` to `.env.local` (use a strong random string)
- [ ] Set up external cron service (e.g., GitHub Actions, cron, Windows Task Scheduler) to call:
  ```bash
  curl -X DELETE https://your-domain.com/api/notifications/cleanup \
    -H "x-cron-secret: your-secret-here"
  ```
- [ ] Schedule to run weekly (recommended: Sunday 2 AM UTC)

**Option C: Manual cleanup**
- [ ] Run periodically: `delete from public.notifications where created_at < now() - interval '90 days';`

## Installation & Build

### Option A: Standalone Deployment (Recommended)

```bash
# The build is already included in the ZIP
# Just ensure dependencies are available
cd .next/standalone
npm install --production
node server.js
```

### Option B: Full Node.js Deployment

```bash
# Install dependencies
npm ci --production

# Build (if not pre-built)
npm run build

# Start production server
npm start
```

### Option C: Using PM2 (Production Process Manager)

```bash
# Install PM2 globally
npm install -g pm2

# Start application
pm2 start npm --name "digital-marketing-portal" -- start

# Save PM2 configuration
pm2 save

# Setup PM2 to start on system boot
pm2 startup
```

## Post-Deployment Verification

### 1. Health Check
```bash
curl http://localhost:3000/api/health
```
Expected response:
```json
{"status":"healthy","timestamp":"...","database":"connected","version":"0.1.0"}
```

### 2. Application Access
- [ ] Homepage loads: `http://your-server:3000`
- [ ] Login page accessible: `http://your-server:3000/login`
- [ ] Dashboard accessible after authentication

### 3. Functionality Tests
- [ ] User authentication works
- [ ] Dashboard displays correctly
- [ ] User Management (IT Admin only)
- [ ] Client Management
- [ ] Calendar entries creation/viewing
- [ ] Reports generation
- [ ] File uploads

## Server Configuration

### Firewall Rules
```bash
# Allow port 3000 (or your configured port)
sudo ufw allow 3000/tcp
```

### Reverse Proxy (Nginx Example)
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### SSL/TLS (Let's Encrypt Example)
```bash
sudo certbot --nginx -d your-domain.com
```

## Security Checklist

- [ ] `.env.local` file permissions set to 600 (readable by owner only)
- [ ] Firewall configured properly
- [ ] SSL/TLS certificate installed (if using HTTPS)
- [ ] Security headers enabled (configured in `next.config.ts`)
- [ ] Rate limiting active (configured in `middleware.ts`)
- [ ] Database RLS policies enabled
- [ ] Strong passwords for service accounts

## Monitoring & Maintenance

### Logs
```bash
# Application logs (PM2)
pm2 logs digital-marketing-portal

# System logs
journalctl -u your-service-name -f
```

### Updates
1. Backup current deployment
2. Extract new ZIP
3. Update `.env.local` if needed
4. Run `npm ci --production`
5. Restart application

### Backup Strategy
- [ ] Database backups configured
- [ ] Application files backup scheduled
- [ ] `.env.local` backed up securely

## Troubleshooting

### Issue: Application won't start
- Check Node.js version: `node --version`
- Verify environment variables are set
- Check port availability: `netstat -tuln | grep 3000`
- Review application logs

### Issue: Database connection fails
- Verify Supabase URL and keys in `.env.local`
- Check database status in Supabase dashboard
- Verify network connectivity to Supabase

### Issue: Build errors
- Clear `.next` directory: `rm -rf .next`
- Rebuild: `npm run build`
- Check Node.js version compatibility

## Rollback Procedure

1. Stop current application
2. Restore previous deployment from backup
3. Restart application
4. Verify health check

## Support & Documentation

- Migration Guide: `SUPABASE_MIGRATION_GUIDE.docx`
- Application README: `README.md`
- API Documentation: Check `/api/health` endpoint

## Deployment Sign-Off

- [ ] Pre-deployment checklist completed
- [ ] Environment configured correctly
- [ ] Application deployed and running
- [ ] All functionality tests passed
- [ ] Security measures verified
- [ ] Monitoring configured
- [ ] Team notified of deployment

---

**Deployed By**: _________________  
**Date**: _________________  
**Version**: V2  
**Deployment Environment**: _________________

