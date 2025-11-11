#!/bin/bash

# Digital Marketing Portal Start Script
echo "🚀 Starting Digital Marketing Portal..."

# Check if .env.local exists
if [ ! -f ".env.local" ]; then
    echo "❌ Environment file not found. Please run setup.sh first."
    exit 1
fi

# Check if Supabase credentials are set
if ! grep -q "NEXT_PUBLIC_SUPABASE_URL" .env.local || ! grep -q "NEXT_PUBLIC_SUPABASE_ANON_KEY" .env.local; then
    echo "⚠️  Supabase credentials not configured in .env.local"
    echo "Please update your environment variables before starting."
    exit 1
fi

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Start development server
echo "🌐 Starting development server on http://localhost:3000"
npm run dev


