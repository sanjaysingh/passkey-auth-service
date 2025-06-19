#!/bin/bash

echo "🔐 Setting up Auth Service"
echo "========================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    echo -e "${RED}Error: Wrangler CLI is not installed.${NC}"
    echo "Please install it with: npm install -g wrangler"
    exit 1
fi

# Check if user is logged in
if ! wrangler whoami &> /dev/null; then
    echo -e "${YELLOW}You need to log in to Cloudflare first.${NC}"
    echo "Run: wrangler login"
    exit 1
fi

echo -e "${GREEN}✓ Wrangler CLI is installed and you're logged in.${NC}"
echo ""

# Install dependencies
echo -e "${BLUE}Installing dependencies...${NC}"
if ! npm install; then
    echo -e "${RED}✗ Failed to install dependencies${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Create KV namespace
echo -e "${BLUE}Creating KV namespace for Auth Service...${NC}"
AUTH_KV_ID=$(wrangler kv namespace create "AUTH_KV" | grep -o 'id = "[^"]*"' | cut -d'"' -f2)

if [ ! -z "$AUTH_KV_ID" ]; then
    echo -e "${GREEN}✓ Auth Service KV namespace created${NC}"
    echo "  Production ID: $AUTH_KV_ID"
    
    # Update wrangler.toml with the new KV namespace ID
    sed -i.bak "s/957c5355339e46f091718c43afbc443a/$AUTH_KV_ID/g" wrangler.toml
    rm wrangler.toml.bak 2>/dev/null || true
    
    echo -e "${GREEN}✓ wrangler.toml updated with KV namespace ID${NC}"
else
    echo -e "${RED}✗ Failed to create Auth Service KV namespace${NC}"
    exit 1
fi

# Deploy initial configuration to KV store
echo ""
echo -e "${BLUE}Deploying initial configuration to KV store...${NC}"

# Check if config.json exists
if [ ! -f "config.json" ]; then
    echo -e "${RED}✗ config.json not found${NC}"
    exit 1
fi

# Read the User.Registration.Allowed setting from config.json
if command -v node &> /dev/null; then
    REGISTRATION_ALLOWED=$(node -p "JSON.parse(require('fs').readFileSync('config.json', 'utf8'))['User.Registration.Allowed']")
    
    # Deploy configuration to KV store
    if wrangler kv:key put --binding=AUTH_KV "config:User.Registration.Allowed" "$REGISTRATION_ALLOWED"; then
        echo -e "${GREEN}✓ Configuration deployed to KV store${NC}"
        echo "  User.Registration.Allowed: $REGISTRATION_ALLOWED"
    else
        echo -e "${RED}✗ Failed to deploy configuration to KV store${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ Node.js not found, skipping configuration deployment${NC}"
    echo "  You'll need to manually set the configuration using:"
    echo "  wrangler kv:key put --binding=AUTH_KV \"config:User.Registration.Allowed\" \"true\""
fi

echo ""
echo -e "${GREEN}✅ Auth Service setup complete!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Update domain configuration in wrangler.toml"
echo "2. Run 'npm run deploy' to deploy the service"
echo "3. To disable registration, update config.json and redeploy" 