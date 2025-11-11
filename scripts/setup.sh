#!/bin/bash

# Digital Marketing Portal Setup Script
echo "🚀 Setting up Digital Marketing Portal..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18+ is required. Current version: $(node -v)"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Check if .env.local exists
if [ ! -f ".env.local" ]; then
    echo "📝 Creating environment file..."
    cp env.example .env.local
    echo "⚠️  Please update .env.local with your Supabase credentials"
else
    echo "✅ Environment file already exists"
fi

# Run linting
echo "🔍 Running code quality checks..."
npm run lint

# Build check
echo "🏗️  Testing build..."
npm run build

echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Update .env.local with your Supabase credentials"
echo "2. Set up your Supabase database (see DEPLOYMENT.md)"
echo "3. Run 'npm run dev' to start development server"
echo ""
echo "📚 For detailed instructions, see DEPLOYMENT.md"


