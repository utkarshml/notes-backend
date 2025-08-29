#!/bin/bash

set -e

echo "🚀 Starting deployment process..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if environment is provided
if [ -z "$1" ]; then
    echo -e "${RED}❌ Please provide environment: ./deploy.sh [staging|production]${NC}"
    exit 1
fi

ENVIRONMENT=$1

echo -e "${YELLOW}📦 Building application...${NC}"
npm run build

echo -e "${YELLOW}🧪 Running type check...${NC}"
npm run lint

echo -e "${YELLOW}🔍 Checking environment variables...${NC}"
if [ ! -f .env ]; then
    echo -e "${RED}❌ .env file not found${NC}"
    exit 1
fi

# Check required environment variables
REQUIRED_VARS=("MONGO_URI" "JWT_SECRET" "EMAIL_USER" "EMAIL_PASS" "GOOGLE_CLIENT_ID")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "$(grep "^${var}=" .env | cut -d '=' -f2)" ]; then
        echo -e "${RED}❌ Missing required environment variable: ${var}${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ Pre-deployment checks passed${NC}"

if [ "$ENVIRONMENT" == "production" ]; then
    echo -e "${YELLOW}🌐 Deploying to production...${NC}"
    # Add your production deployment commands here
    # For example: Railway, Render, or Docker deployment
elif [ "$ENVIRONMENT" == "staging" ]; then
    echo -e "${YELLOW}🔧 Deploying to staging...${NC}"
    # Add your staging deployment commands here
fi

echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
