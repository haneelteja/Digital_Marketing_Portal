@echo off
echo 🚀 Starting Digital Marketing Portal...

REM Check if .env.local exists
if not exist ".env.local" (
    echo ❌ Environment file not found. Please run setup.bat first.
    pause
    exit /b 1
)

REM Check if Supabase credentials are set
findstr /C:"NEXT_PUBLIC_SUPABASE_URL" .env.local >nul
if %errorlevel% neq 0 (
    echo ⚠️  Supabase credentials not configured in .env.local
    echo Please update your environment variables before starting.
    pause
    exit /b 1
)

REM Check if dependencies are installed
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    npm install
)

REM Start development server
echo 🌐 Starting development server on http://localhost:3000
npm run dev


