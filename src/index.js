import { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { isoUint8Array, isoBase64URL } from '@simplewebauthn/server/helpers';
import { SignJWT, jwtVerify } from 'jose';

// Helper function to log with context
function log(level, message, context = {}) {
  const timestamp = new Date().toISOString();
  const logData = {
    timestamp,
    level,
    message,
    ...context
  };
  console.log(JSON.stringify(logData));
}

// Helper function to generate JWT secret
async function getJWTSecret(env) {
  const encoder = new TextEncoder();
  const secretString = env.JWT_SECRET;
  
  if (!secretString) {
    throw new Error('JWT_SECRET environment variable is required');
  }
  
  
  return await crypto.subtle.importKey(
    'raw',
    encoder.encode(secretString),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

// Helper function to create JWT token
async function createJWT(userId, env) {
  const secret = await getJWTSecret(env);
  const now = Math.floor(Date.now() / 1000);
  const jwt = await new SignJWT({ 
    userId,
    iat: now,      // Issued at
    exp: now + (1 * 60 * 60)  // Expires in 1 hour (3600 seconds)
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')  // 1 hour expiration
    .setNotBefore('0s')       // Valid immediately
    .sign(secret);
  
  return jwt;
}

// Helper function to verify JWT token
async function verifyJWT(token, env) {
  try {
    const secret = await getJWTSecret(env);
    const { payload } = await jwtVerify(token, secret, {
      clockTolerance: '30s',  // Allow 30 seconds clock skew
      maxTokenAge: '1h'       // Maximum age of 1 hour
    });
    
    // Additional explicit expiration check
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return null;
    }
    
    return payload;
  } catch (error) {
    return null;
  }
}

// Helper function to get user data
async function getUser(env, userId) {
  const userData = await env.AUTH_KV.get(`user:${userId}`);
  return userData ? JSON.parse(userData) : null;
}

// Helper function to save user data
async function saveUser(env, userId, userData) {
  await env.AUTH_KV.put(`user:${userId}`, JSON.stringify(userData));
}

// Helper function to find user by credential ID (for usernameless authentication)
async function findUserByCredentialId(env, credentialId) {
  // Since we use credential ID as the primary key, directly get the user
  return await getUser(env, credentialId);
}

// Helper function to validate username
function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username must be a non-empty string' };
  }
  
  if (username.length < 3 || username.length > 50) {
    return { valid: false, error: 'Username must be between 3 and 50 characters' };
  }
  
  if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
    return { valid: false, error: 'Username can only contain letters, numbers, dots, underscores, and hyphens' };
  }
  
  return { valid: true };
}

// Helper function to check if origin is allowed (subdomain of sanjaysingh.net)
function isAllowedOrigin(origin) {
  if (!origin) return false;
  
  try {
    const url = new URL(origin);
    
    // Allow exact domain and all subdomains of sanjaysingh.net
    if (url.hostname === 'sanjaysingh.net' || url.hostname.endsWith('.sanjaysingh.net')) {
      return true;
    }
    
    // Localhost access removed for security - use proper domains only
    
    return false;
  } catch (error) {
    return false;
  }
}

// CORS headers with security headers
function getCorsHeaders(origin) {
  // Check if the origin is allowed
  const allowOrigin = isAllowedOrigin(origin) ? origin : 'https://sanjaysingh.net';
  
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    // Security headers
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'none'",
  };
}

// Handle OPTIONS requests for CORS
function handleOptions(origin) {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders(origin),
  });
}

// Helper function to serialize registration options for JSON transmission
function serializeRegistrationOptions(options) {
  return {
    ...options,
    user: {
      ...options.user,
      id: options.user.id instanceof Uint8Array ? isoBase64URL.fromBuffer(options.user.id) :
          (typeof options.user.id === 'string' ? options.user.id : isoBase64URL.fromBuffer(options.user.id))
    },
    challenge: options.challenge instanceof Uint8Array ? isoBase64URL.fromBuffer(options.challenge) :
               (typeof options.challenge === 'string' ? options.challenge : isoBase64URL.fromBuffer(options.challenge)),
    excludeCredentials: options.excludeCredentials?.map(cred => ({
      ...cred,
      id: cred.id instanceof Uint8Array ? isoBase64URL.fromBuffer(cred.id) :
          (typeof cred.id === 'string' ? cred.id : isoBase64URL.fromBuffer(cred.id))
    })) || []
  };
}

// Helper function to serialize authentication options for JSON transmission
function serializeAuthenticationOptions(options) {
  return {
    ...options,
    challenge: options.challenge instanceof Uint8Array ? isoBase64URL.fromBuffer(options.challenge) :
               (typeof options.challenge === 'string' ? options.challenge : isoBase64URL.fromBuffer(options.challenge)),
    allowCredentials: options.allowCredentials?.map(cred => ({
      ...cred,
      id: cred.id instanceof Uint8Array ? isoBase64URL.fromBuffer(cred.id) : 
          (typeof cred.id === 'string' ? cred.id : isoBase64URL.fromBuffer(cred.id))
    })) || []
  };
}

// Helper functions for base64 encoding/decoding (Buffer replacement for Cloudflare Workers)
function uint8ArrayToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8Array(base64) {
  if (!base64 || typeof base64 !== 'string') {
    throw new Error('Invalid base64 input: expected non-empty string');
  }
  
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch (error) {
    throw new Error(`Failed to decode base64 string: ${error.message}`);
  }
}

function base64UrlToUint8Array(base64url) {
  if (!base64url || typeof base64url !== 'string') {
    throw new Error('Invalid base64url input: expected non-empty string');
  }
  
  try {
    // Convert base64url to base64
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    const padding = base64.length % 4;
    const paddedBase64 = padding ? base64 + '='.repeat(4 - padding) : base64;
    return base64ToUint8Array(paddedBase64);
  } catch (error) {
    throw new Error(`Failed to decode base64url string: ${error.message}`);
  }
}

// Helper function to convert base64 to base64URL
function base64ToBase64Url(base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Helper function to convert base64URL to base64
function base64UrlToBase64(base64url) {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  return base64;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const origin = request.headers.get('Origin');
    
    // Log incoming request
    log('info', 'Request', { method, path, origin });

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return handleOptions(origin);
    }

    try {
      let result;
      switch (path) {
        case '/auth/register/begin':
          result = await handleRegistrationBegin(request, env, origin);
          break;
        case '/auth/register/complete':
          result = await handleRegistrationComplete(request, env, origin);
          break;
        case '/auth/login/begin':
          result = await handleAuthenticationBegin(request, env, origin);
          break;
        case '/auth/login/complete':
          result = await handleAuthenticationComplete(request, env, origin);
          break;
        case '/auth/verify':
          result = await handleTokenVerification(request, env, origin);
          break;
        case '/auth/user':
          result = await handleGetUser(request, env, origin);
          break;
        default:
          log('warn', 'Unknown endpoint', { path, method });
          result = new Response('Not Found', { 
            status: 404,
            headers: getCorsHeaders(origin)
          });
      }
      
      return result;
    } catch (error) {
      log('error', 'Request failed', {
        path,
        method,
        error: error.message
      });
      
      return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...getCorsHeaders(origin)
        }
      });
    }
  }
};

async function handleRegistrationBegin(request, env, origin) {
  const { username } = await request.json();
  
  log('info', 'Registration begin', { origin });
  
  const usernameValidation = validateUsername(username);
  if (!usernameValidation.valid) {
    log('warn', 'Registration failed - invalid username');
    return new Response(JSON.stringify({ error: usernameValidation.error }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  // We'll use the credential ID as the user ID, but we don't have it yet
  // So we'll generate a temporary ID for the WebAuthn userID field
  const tempUserId = crypto.randomUUID();
  
  const options = await generateRegistrationOptions({
    rpName: env.RP_NAME,
    rpID: env.RP_ID,
    userID: isoUint8Array.fromUTF8String(tempUserId),
    userName: username,
    userDisplayName: username,
    attestationType: 'none',
    excludeCredentials: [],
    authenticatorSelection: {
      userVerification: 'preferred',
    },
    timeout: 60000,
  });

  const serializedOptions = serializeRegistrationOptions(options);

  await env.AUTH_KV.put(
    `challenge:${serializedOptions.challenge}`, 
    JSON.stringify({ tempUserId, username, originalChallenge: options.challenge }), 
    { expirationTtl: 300 }
  );

  log('info', 'Registration challenge created');

  return new Response(JSON.stringify(serializedOptions), {
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
  });
}

async function handleRegistrationComplete(request, env, origin) {
  const body = await request.json();
  
  log('info', 'Registration complete attempt', { origin });

  // Extract challenge from clientDataJSON
  let challenge;
  try {
    const clientDataJSON = JSON.parse(atob(body.response.clientDataJSON));
    challenge = clientDataJSON.challenge;
  } catch (error) {
    log('error', 'Failed to extract challenge', { error: error.message });
    return new Response(JSON.stringify({ error: 'Invalid client data' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  // Get stored challenge data
  const challengeData = await env.AUTH_KV.get(`challenge:${challenge}`);
  
  if (!challengeData) {
    log('warn', 'Registration failed - invalid or expired challenge');
    return new Response(JSON.stringify({ error: 'Invalid or expired challenge' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const { tempUserId, username, originalChallenge } = JSON.parse(challengeData);
  log('info', 'Challenge validated');

  const expectedOrigin = isAllowedOrigin(origin) ? origin : env.ORIGIN;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: originalChallenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: env.RP_ID,
    });
  } catch (error) {
    log('error', 'Registration verification failed', {
      error: error.message
    });
    return new Response(JSON.stringify({ error: `Verification failed: ${error.message}` }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  if (verification.verified) {
    // Save user data using credential ID as the primary key
    const userData = {
      id: body.id, // Use credential ID as user ID
      username,
      credentials: [{
        credentialID: body.id,
        credentialPublicKey: uint8ArrayToBase64(verification.registrationInfo.credentialPublicKey),
        counter: verification.registrationInfo.counter,
        transports: body.response.transports || [],
        createdAt: new Date().toISOString()
      }],
      createdAt: new Date().toISOString()
    };

    // Store user data with credential ID as the key - only 1 KV entry needed!
    await saveUser(env, body.id, userData);
    
    // Clean up challenge
    await env.AUTH_KV.delete(`challenge:${challenge}`);

    // Create JWT token using credential ID
    const token = await createJWT(body.id, env);

    log('info', 'Registration successful');

    return new Response(JSON.stringify({ 
      verified: true, 
      token,
      user: { id: body.id, username }
    }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  log('warn', 'Registration verification failed');
  return new Response(JSON.stringify({ verified: false }), {
    status: 400,
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
  });
}

async function handleAuthenticationBegin(request, env, origin) {
  const body = await request.json();
  const { username } = body;
  
  log('info', 'Authentication begin', { origin });
  
  try {
    const options = await generateAuthenticationOptions({
      rpID: env.RP_ID,
      allowCredentials: [],
      userVerification: 'preferred',
    });

    const serializedOptions = serializeAuthenticationOptions(options);

    await env.AUTH_KV.put(
      `auth-challenge:${serializedOptions.challenge}`, 
      JSON.stringify({ type: 'usernameless', timestamp: Date.now() }), 
      { expirationTtl: 300 }
    );

    log('info', 'Authentication challenge created');

    return new Response(JSON.stringify(serializedOptions), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  } catch (error) {
    log('error', 'Failed to generate authentication options', {
      error: error.message
    });
    
    return new Response(JSON.stringify({ error: 'Failed to generate authentication options' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }
}

async function handleAuthenticationComplete(request, env, origin) {
  const body = await request.json();
  
  log('info', 'Authentication complete attempt', { origin });

  // Validate body.id before processing
  if (!body.id || typeof body.id !== 'string') {
    log('error', 'Authentication failed - invalid credential ID');
    return new Response(JSON.stringify({ error: 'Invalid credential ID' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }
  
  // Extract challenge from clientDataJSON
  let challenge;
  try {
    const clientDataJSON = JSON.parse(atob(body.response.clientDataJSON));
    challenge = clientDataJSON.challenge;
  } catch (error) {
    log('error', 'Failed to extract challenge from clientDataJSON', { error: error.message });
    return new Response(JSON.stringify({ error: 'Invalid client data' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  // Get stored challenge data for usernameless authentication
  const challengeData = await env.AUTH_KV.get(`auth-challenge:${challenge}`);
  if (!challengeData) {
    log('warn', 'Authentication failed - invalid or expired challenge');
    return new Response(JSON.stringify({ error: 'Invalid or expired challenge' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  let challengeInfo;
  try {
    challengeInfo = JSON.parse(challengeData);
  } catch (error) {
    // Handle legacy challenge format (just userId as string)
    challengeInfo = { type: 'legacy', userId: challengeData };
  }

  let user;
  if (challengeInfo.type === 'usernameless') {
    user = await findUserByCredentialId(env, body.id);
    if (!user) {
      log('warn', 'Usernameless authentication failed - no user found for credential');
      return new Response(JSON.stringify({ error: 'No user found for this credential' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
      });
    }
  } else {
    // Legacy format - get user by stored userId (for backward compatibility)
    const userId = challengeInfo.userId || challengeInfo;
    user = await getUser(env, userId);
    if (!user) {
      log('error', 'Authentication failed - user not found');
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
      });
    }
  }

  // Find the credential being used
  let credential = user.credentials.find(cred => cred.credentialID === body.id);
  
  if (!credential) {
    log('warn', 'Authentication failed - credential not found');
    return new Response(JSON.stringify({ error: 'Credential not found' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const expectedOrigin = isAllowedOrigin(origin) ? origin : env.ORIGIN;

  let verification;
  try {
    // Convert the stored base64URL credential ID back to base64 for verification
    const credentialIdBase64 = base64UrlToBase64(credential.credentialID);
    
    verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: challenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: env.RP_ID,
      authenticator: {
        credentialID: base64ToUint8Array(credentialIdBase64),
        credentialPublicKey: base64ToUint8Array(credential.credentialPublicKey),
        counter: credential.counter,
        transports: credential.transports,
      },
    });
  } catch (error) {
    log('error', 'Authentication verification failed', {
      error: error.message
    });
    return new Response(JSON.stringify({ error: 'Verification failed' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  if (verification.verified) {
    // Update counter
    credential.counter = verification.authenticationInfo.newCounter;
    await saveUser(env, user.id, user);
    
    // Clean up challenge
    await env.AUTH_KV.delete(`auth-challenge:${challenge}`);

    // Create JWT token using credential ID
    const token = await createJWT(user.id, env);

    log('info', 'Authentication successful', { 
      authType: challengeInfo.type || 'legacy'
    });

    return new Response(JSON.stringify({ 
      verified: true, 
      token,
      user: { id: user.id, username: user.username }
    }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  log('warn', 'Authentication failed - verification returned false');
  return new Response(JSON.stringify({ verified: false }), {
    status: 400,
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
  });
}

async function handleTokenVerification(request, env, origin) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Missing or invalid token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const token = authHeader.substring(7);
  const payload = await verifyJWT(token, env);
  
  if (!payload) {
    return new Response(JSON.stringify({ error: 'Invalid token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const user = await getUser(env, payload.userId);
  if (!user) {
    return new Response(JSON.stringify({ error: 'User not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  return new Response(JSON.stringify({ 
    valid: true, 
    userId: payload.userId,
    user: { id: user.id, username: user.username }
  }), {
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
  });
}

async function handleGetUser(request, env, origin) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Missing or invalid token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const token = authHeader.substring(7);
  const payload = await verifyJWT(token, env);
  
  if (!payload) {
    return new Response(JSON.stringify({ error: 'Invalid token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const user = await getUser(env, payload.userId);
  if (!user) {
    return new Response(JSON.stringify({ error: 'User not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  return new Response(JSON.stringify({ 
    id: user.id, 
    username: user.username,
    createdAt: user.createdAt
  }), {
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
  });
} 