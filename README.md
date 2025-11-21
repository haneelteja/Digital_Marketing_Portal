- **👥 Client Management** - Complete client database with contact info
- **📊 Analytics & Reports** - Export data to Excel/PDF formats
- **📁 File Management** - Upload and organize marketing assets
- **🔐 Secure Authentication** - Supabase-powered user management
- **📱 Responsive Design** - Works on desktop, tablet, and mobile

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Supabase account

### 1. Setup (Automated)
```bash
# Clone and setup in one command
git clone <your-repo-url>
cd Digital_Marketing_Portal_Backup_2025-09-26_21-31-42
npm run setup
```

### 2. Configure Environment
```bash
# Edit .env.local with your Supabase credentials
NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
```

### 3. Setup Database
1. Create Supabase project at [supabase.com](https://supabase.com)
2. Run SQL scripts: `fix_rls_policies.sql` and `test_rls_policies.sql`
3. See `DATABASE_SETUP.md` for detailed instructions

### 4. Start Application
```bash
npm run start:dev
```

Visit: `http://localhost:3000`

## 📚 Documentation

- **[QUICK_START.md](QUICK_START.md)** - Get up and running in 5 minutes
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide
- **[DATABASE_SETUP.md](DATABASE_SETUP.md)** - Database configuration
- **[Security & Performance](DEPLOYMENT.md#security-features)** - Built-in security features

## 🛠️ Development

### Available Scripts
```bash
npm run dev              # Start development server
npm run build              # Build for production
npm run start             # Start production server
npm run lint              # Check code quality
npm run lint:fix          # Fix linting issues
npm run type-check        # TypeScript validation
npm run health            # Health check
npm run audit             # Security audit
```

### Docker Support
```bash
npm run docker:build      # Build Docker image
npm run docker:run        # Run with Docker
npm run docker:compose    # Run with Docker Compose
```

## 🏗️ Architecture

- **Frontend**: Next.js 15 with App Router
- **Backend**: Supabase (PostgreSQL + Auth + Storage)
- **Styling**: Tailwind CSS
- **Type Safety**: TypeScript
- **Security**: Row Level Security (RLS)
- **File Processing**: ExcelJS, jsPDF

## 🔐 Security Features

- Row Level Security (RLS) enabled
- Input validation and sanitization
- Secure file uploads
- XSS protection
- CSRF protection
- Secure headers

## 📊 Performance

- Virtualized lists for large datasets
- Optimized database queries
- Client-side caching
- Image optimization
- Bundle optimization

## 🚀 Deployment Options

### Vercel (Recommended)
1. Connect GitHub repository
2. Add environment variables
3. Deploy automatically

### Docker
```bash
docker build -t digital-marketing-portal .
docker run -p 3000:3000 digital-marketing-portal
```

### Manual
```bash
npm run build
npm start
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

- Check `QUICK_START.md` for common issues
- Review `DEPLOYMENT.md` for deployment help
- Run `npm run health` for application status
