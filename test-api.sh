#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BASE_URL="http://localhost:5000/api"
EMAIL="test@example.com"
TOKEN=""

echo -e "${YELLOW}🧪 Testing API endpoints...${NC}"

# Test health endpoint
echo -e "${YELLOW}1. Testing health endpoint...${NC}"
HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/health)
if [ "$HEALTH_RESPONSE" == "200" ]; then
    echo -e "${GREEN}✅ Health check passed${NC}"
else
    echo -e "${RED}❌ Health check failed (Status: $HEALTH_RESPONSE)${NC}"
    exit 1
fi

# Test signup
echo -e "${YELLOW}2. Testing email signup...${NC}"
SIGNUP_RESPONSE=$(curl -s -X POST \
  "$BASE_URL/auth/signup" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\"}")

if echo "$SIGNUP_RESPONSE" | grep -q "success.*true"; then
    echo -e "${GREEN}✅ Signup endpoint working${NC}"
else
    echo -e "${RED}❌ Signup endpoint failed${NC}"
    echo "$SIGNUP_RESPONSE"
fi

# Test login
echo -e "${YELLOW}3. Testing email login...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST \
  "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\"}")

if echo "$LOGIN_RESPONSE" | grep -q "success.*true\|User.*not.*found"; then
    echo -e "${GREEN}✅ Login endpoint working${NC}"
else
    echo -e "${RED}❌ Login endpoint failed${NC}"
    echo "$LOGIN_RESPONSE"
fi

# Test protected route without token
echo -e "${YELLOW}4. Testing protected route without token...${NC}"
PROTECTED_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/notes")
if [ "$PROTECTED_RESPONSE" == "401" ]; then
    echo -e "${GREEN}✅ Protected route properly secured${NC}"
else
    echo -e "${RED}❌ Protected route not properly secured (Status: $PROTECTED_RESPONSE)${NC}"
fi

echo -e "${GREEN}🎉 API testing completed!${NC}"
