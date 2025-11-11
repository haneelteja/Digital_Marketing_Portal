@echo off
echo 🚀 Setting up Digital Marketing Portal...

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js 18+ first.
    exit /b 1
)

echo ✅ Node.js version:
node --version

REM Install dependencies
echo 📦 Installing dependencies...
npm install

REM Check if .env.local exists
if not exist ".env.local" (
    echo 📝 Creating environment file...
    copy env.example .env.local
    echo ⚠️  Please update .env.local with your Supabase credentials
) else (
    echo ✅ Environment file already exists
)

REM Run linting
echo 🔍 Running code quality checks...
npm run lint

REM Build check
echo 🏗️  Testing build...
npm run build

echo ✅ Setup complete!
echo.
echo Next steps:
echo 1. Update .env.local with your Supabase credentials
echo 2. Set up your Supabase database (see DEPLOYMENT.md)
echo 3. Run 'npm run dev' to start development server
echo.
echo 📚 For detailed instructions, see DEPLOYMENT.md
pause


