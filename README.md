# Passkey Authentication Service

Production-ready passkey authentication service built for Cloudflare Workers. Provides WebAuthn-based passwordless authentication with JWT token management.

## Features

- 🔐 **Passkey Authentication** - WebAuthn standard for passwordless login
- 🔑 **JWT Tokens** - Secure session management (24h expiry)
- 👥 **User Management** - Registration, login, and user data
- 🚀 **Cloudflare Workers** - Global edge deployment
- 💾 **KV Storage** - User data and credential storage

## Quick Setup

### Prerequisites
- Cloudflare account
- Wrangler CLI: `npm install -g wrangler`
- Authenticated: `wrangler login`

### Local Development
```bash
# Install dependencies
npm install

# Set JWT secret
wrangler secret put JWT_SECRET

# Start development server
wrangler dev

# Deploy to production
wrangler deploy
```

### GitHub Actions Deployment
1. **Set GitHub Secrets**:
   - `CLOUDFLARE_API_TOKEN` - Cloudflare API token
   - `JWT_SECRET` - Random secret: `openssl rand -base64 32`

2. **Push to main branch** - Auto-deploys via GitHub Actions

## Configuration

Domain settings in `wrangler.toml`:
```toml
[vars]
RP_ID = "sanjaysingh.net"                    # Your domain
RP_NAME = "Passkey Auth Service"             # Service name
ORIGIN = "https://auth.sanjaysingh.net"      # Your URL
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register/begin` | Start passkey registration |
| POST | `/auth/register/complete` | Complete passkey registration |
| POST | `/auth/login/begin` | Start passkey authentication |
| POST | `/auth/login/complete` | Complete passkey authentication |
| GET | `/auth/verify` | Verify JWT token |
| GET | `/auth/user` | Get user information |

## Usage Example

```javascript
// Register new user
const registerResponse = await fetch('/auth/register/begin', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'user@example.com' })
});

// Login existing user
const loginResponse = await fetch('/auth/login/begin', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'user@example.com' })
});

// Verify token
const verifyResponse = await fetch('/auth/verify', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

## Security

- JWT tokens expire after 24 hours
- Uses HS256 algorithm for JWT signing
- WebAuthn credentials stored in Cloudflare KV
- HTTPS required in production
- No passwords - passkey-only authentication

## License

MIT 