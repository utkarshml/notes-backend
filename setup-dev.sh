#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔧 Setting up development environment...${NC}"

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}📝 Creating .env file from example...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}⚠️  Please update .env with your actual values${NC}"
fi

# Install dependencies
echo -e "${YELLOW}📦 Installing dependencies...${NC}"
npm install

# Build the project
echo -e "${YELLOW}🏗️  Building project...${NC}"
npm run build

echo -e "${GREEN}✅ Development environment setup complete!${NC}"
echo -e "${YELLOW}📋 Next steps:${NC}"
echo "1. Update .env with your actual values"
echo "2. Start development server: npm run dev"
echo "3. Check health: http://localhost:5000/health"
