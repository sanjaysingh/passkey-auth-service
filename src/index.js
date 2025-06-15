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
  const secretString = env.JWT_SECRET || 'fallback-secret-key';
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
  const jwt = await new SignJWT({ userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('24h')
    .sign(secret);
  return jwt;
}

// Helper function to verify JWT token
async function verifyJWT(token, env) {
  try {
    const secret = await getJWTSecret(env);
    const { payload } = await jwtVerify(token, secret);
    return payload;
  } catch (error) {
    return null;
  }
}

// Helper function to generate user ID
function generateUserId() {
  return crypto.randomUUID();
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

// Helper function to get user by username
async function getUserByUsername(env, username) {
  const userId = await env.AUTH_KV.get(`username:${username}`);
  if (!userId) return null;
  return await getUser(env, userId);
}

// Helper function to save username mapping
async function saveUsernameMapping(env, username, userId) {
  await env.AUTH_KV.put(`username:${username}`, userId);
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
    
    // Allow localhost for development (any port)
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
      return true;
    }
    
    return false;
  } catch (error) {
    return false;
  }
}

// CORS headers
function getCorsHeaders(origin) {
  // Check if the origin is allowed
  const allowOrigin = isAllowedOrigin(origin) ? origin : 'https://sanjaysingh.net';
  
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
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
      id: typeof options.user.id === 'string' ? options.user.id : isoBase64URL.fromBuffer(options.user.id)
    },
    challenge: typeof options.challenge === 'string' ? options.challenge : isoBase64URL.fromBuffer(options.challenge),
    excludeCredentials: options.excludeCredentials?.map(cred => ({
      ...cred,
      id: typeof cred.id === 'string' ? cred.id : isoBase64URL.fromBuffer(cred.id)
    })) || []
  };
}

// Helper function to serialize authentication options for JSON transmission
function serializeAuthenticationOptions(options) {
  return {
    ...options,
    challenge: typeof options.challenge === 'string' ? options.challenge : isoBase64URL.fromBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map(cred => ({
      ...cred,
      id: typeof cred.id === 'string' ? cred.id : isoBase64URL.fromBuffer(cred.id)
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
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlToUint8Array(base64url) {
  // Convert base64url to base64
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padding = base64.length % 4;
  const paddedBase64 = padding ? base64 + '='.repeat(4 - padding) : base64;
  return base64ToUint8Array(paddedBase64);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const origin = request.headers.get('Origin');
    
    // Log incoming request
    log('info', 'Incoming request', {
      method,
      path,
      origin,
      userAgent: request.headers.get('User-Agent')?.substring(0, 100)
    });

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      log('info', 'CORS preflight request', { origin });
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
          log('warn', 'Unknown endpoint accessed', { path, method });
          result = new Response('Not Found', { 
            status: 404,
            headers: getCorsHeaders(origin)
          });
      }
      
      // Log successful response
      log('info', 'Request completed', {
        path,
        method,
        status: result.status,
        responseTime: Date.now() // Basic timing
      });
      
      return result;
    } catch (error) {
      // Enhanced error logging
      log('error', 'Request failed', {
        path,
        method,
        error: error.message,
        stack: error.stack?.substring(0, 500)
      });
      
      console.error('Error:', error);
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
  
  log('info', 'Registration begin', { username, origin });
  
  if (!username) {
    log('warn', 'Registration failed - no username', { origin });
    return new Response(JSON.stringify({ error: 'Username is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  // Check if user already exists
  const existingUser = await getUserByUsername(env, username);
  if (existingUser) {
    log('warn', 'Registration failed - user exists', { username });
    return new Response(JSON.stringify({ error: 'User already exists' }), {
      status: 409,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const userId = generateUserId();
  
  const options = await generateRegistrationOptions({
    rpName: env.RP_NAME,
    rpID: env.RP_ID,
    userID: isoUint8Array.fromUTF8String(userId),
    userName: username,
    userDisplayName: username,
    attestationType: 'none',
    excludeCredentials: [],
    authenticatorSelection: {
      userVerification: 'preferred',
    },
    timeout: 60000,
  });

  // Serialize options for client
  const serializedOptions = serializeRegistrationOptions(options);

  // Store challenge and user info temporarily using the serialized challenge
  await env.AUTH_KV.put(
    `challenge:${serializedOptions.challenge}`, 
    JSON.stringify({ userId, username, originalChallenge: options.challenge }), 
    { expirationTtl: 300 } // 5 minutes
  );

  log('info', 'Registration challenge created', { 
    username, 
    userId, 
    challengeLength: serializedOptions.challenge.length 
  });

  return new Response(JSON.stringify(serializedOptions), {
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
  });
}

async function handleRegistrationComplete(request, env, origin) {
  const body = await request.json();
  
  log('info', 'Registration complete attempt', { 
    credentialId: body.id,
    origin 
  });

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
    log('warn', 'Registration failed - invalid challenge', { challenge: challenge.substring(0, 10) + '...' });
    return new Response(JSON.stringify({ error: 'Invalid or expired challenge' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const { userId, username, originalChallenge } = JSON.parse(challengeData);
  log('info', 'Challenge validated', { username, userId });

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
      username,
      error: error.message,
      expectedOrigin,
      expectedRPID: env.RP_ID
    });
    return new Response(JSON.stringify({ error: `Verification failed: ${error.message}` }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  if (verification.verified) {
    // Save user data
    const userData = {
      id: userId,
      username,
      credentials: [{
        credentialID: uint8ArrayToBase64(verification.registrationInfo.credentialID),
        credentialPublicKey: uint8ArrayToBase64(verification.registrationInfo.credentialPublicKey),
        counter: verification.registrationInfo.counter,
        transports: body.response.transports || [],
        createdAt: new Date().toISOString()
      }],
      createdAt: new Date().toISOString()
    };

    await saveUser(env, userId, userData);
    await saveUsernameMapping(env, username, userId);
    
    // Clean up challenge
    await env.AUTH_KV.delete(`challenge:${challenge}`);

    // Create JWT token
    const token = await createJWT(userId, env);

    log('info', 'Registration successful', { 
      username, 
      userId,
      credentialId: body.id
    });

    return new Response(JSON.stringify({ 
      verified: true, 
      token,
      user: { id: userId, username }
    }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  log('warn', 'Registration verification failed', { username });
  return new Response(JSON.stringify({ verified: false }), {
    status: 400,
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
  });
}

async function handleAuthenticationBegin(request, env, origin) {
  const { username } = await request.json();
  
  if (!username) {
    return new Response(JSON.stringify({ error: 'Username is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const user = await getUserByUsername(env, username);
  if (!user) {
    return new Response(JSON.stringify({ error: 'User not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const options = await generateAuthenticationOptions({
    rpID: env.RP_ID,
    allowCredentials: user.credentials.map(cred => ({
      id: base64ToUint8Array(cred.credentialID),
      type: 'public-key',
      transports: cred.transports,
    })),
    userVerification: 'preferred',
  });

  // Serialize options for client
  const serializedOptions = serializeAuthenticationOptions(options);

  // Store challenge with user ID using the serialized challenge
  await env.AUTH_KV.put(
    `auth-challenge:${serializedOptions.challenge}`, 
    user.id, 
    { expirationTtl: 300 } // 5 minutes
  );

  return new Response(JSON.stringify(serializedOptions), {
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
  });
}

async function handleAuthenticationComplete(request, env, origin) {
  const body = await request.json();
  
  // Extract challenge from clientDataJSON
  let challenge;
  try {
    const clientDataJSON = JSON.parse(atob(body.response.clientDataJSON));
    challenge = clientDataJSON.challenge;
  } catch (error) {
    console.error('Failed to extract challenge from clientDataJSON:', error);
    return new Response(JSON.stringify({ error: 'Invalid client data' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  // Get stored user ID for this challenge
  const userId = await env.AUTH_KV.get(`auth-challenge:${challenge}`);
  if (!userId) {
    return new Response(JSON.stringify({ error: 'Invalid or expired challenge' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const user = await getUser(env, userId);
  if (!user) {
    return new Response(JSON.stringify({ error: 'User not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  // Find the credential being used
  const credentialID = uint8ArrayToBase64(base64UrlToUint8Array(body.id));
  const credential = user.credentials.find(cred => cred.credentialID === credentialID);
  
  if (!credential) {
    return new Response(JSON.stringify({ error: 'Credential not found' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  const expectedOrigin = isAllowedOrigin(origin) ? origin : env.ORIGIN;

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: challenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: env.RP_ID,
      authenticator: {
        credentialID: base64ToUint8Array(credential.credentialID),
        credentialPublicKey: base64ToUint8Array(credential.credentialPublicKey),
        counter: credential.counter,
        transports: credential.transports,
      },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Verification failed' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

  if (verification.verified) {
    // Update counter
    credential.counter = verification.authenticationInfo.newCounter;
    await saveUser(env, userId, user);
    
    // Clean up challenge
    await env.AUTH_KV.delete(`auth-challenge:${challenge}`);

    // Create JWT token
    const token = await createJWT(userId, env);

    return new Response(JSON.stringify({ 
      verified: true, 
      token,
      user: { id: userId, username: user.username }
    }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) }
    });
  }

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