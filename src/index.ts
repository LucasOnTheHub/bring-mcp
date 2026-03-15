#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import crypto from 'node:crypto';
import http, { IncomingMessage, ServerResponse } from 'node:http';
import { z, ZodRawShape, ZodObject } from 'zod';
import { BringClient } from './bringClient.js';
import 'dotenv/config';

import { registerListTools } from './tools/listTools.js';
import { registerItemTools } from './tools/itemTools.js';
import { registerUserTools } from './tools/userTools.js';
import { registerCatalogTools } from './tools/catalogTools.js';

const server = new McpServer({
  name: 'bring',
  version: '1.0.0',
});

// Define a type for content parts
type McpContentPart = { type: 'text'; text: string; [key: string]: unknown };

// Helper function to create a simple text response
function textToolResult(text: string) {
  const contentPart: McpContentPart = { type: 'text', text };
  return { content: [contentPart] };
}

// Helper function to create a JSON response (as stringified text)
function jsonToolResult(data: unknown) {
  const contentPart: McpContentPart = { type: 'text', text: JSON.stringify(data, null, 2) };
  return { content: [contentPart] };
}

// Generic tool registration helper - Overloads
export function registerTool<TParams extends ZodRawShape, TResult, TArgs = z.infer<ZodObject<TParams>>>(options: {
  server: McpServer;
  bc: BringClient;
  name: string;
  description: string;
  schemaShape: TParams; // Non-optional for this overload
  actionFn: (args: TArgs, bc: BringClient) => Promise<TResult>;
  transformResult?: (result: TResult) => { content: McpContentPart[] };
  failureMessage: string;
}): void;
export function registerTool<TResult>(options: {
  server: McpServer;
  bc: BringClient;
  name: string;
  description: string;
  schemaShape?: undefined; // Schema is undefined for this overload
  actionFn: (args: undefined, bc: BringClient) => Promise<TResult>; // Args are undefined
  transformResult?: (result: TResult) => { content: McpContentPart[] };
  failureMessage: string;
}): void;
// Implementation signature for registerTool
export function registerTool(options: {
  server: McpServer;
  bc: BringClient;
  name: string;
  description: string;
  schemaShape?: ZodRawShape;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  actionFn: (args: any, bc: BringClient) => Promise<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transformResult?: (result: any) => { content: McpContentPart[] };
  failureMessage: string;
}) {
  const { server, bc, name, description, schemaShape, actionFn, transformResult, failureMessage } = options;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const callback = async (args: any) => {
    try {
      const res = await actionFn(args, bc);
      if (transformResult) {
        return transformResult(res);
      }
      return jsonToolResult(res);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error(`${failureMessage}:`, error);
      return textToolResult(`${failureMessage}: ${errorMessage}`);
    }
  };

  if (schemaShape) {
    server.tool(name, description, schemaShape, callback);
  } else {
    server.tool(name, description, {}, callback);
  }
}

async function readRequestBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      try {
        const body = Buffer.concat(chunks).toString('utf-8');
        resolve(body ? JSON.parse(body) : undefined);
      } catch {
        reject(new Error('Invalid JSON in request body'));
      }
    });
    req.on('error', reject);
  });
}

function setCorsHeaders(res: ServerResponse, origin: string | undefined, allowedOrigin: string): void {
  // Reflect the request Origin only when CORS_ORIGIN is a specific domain, otherwise use wildcard
  const effectiveOrigin = allowedOrigin === '*' ? '*' : (origin ?? '*');
  res.setHeader('Access-Control-Allow-Origin', effectiveOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Accept, Authorization, x-api-key, Mcp-Session-Id, Last-Event-ID',
  );
  res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function isAuthenticated(req: IncomingMessage, apiKey: string | undefined): boolean {
  if (!apiKey) return true; // No MCP_API_KEY set: open access
  const auth = req.headers['authorization'];
  if (auth?.startsWith('Bearer ') && auth.slice(7) === apiKey) return true;
  if (req.headers['x-api-key'] === apiKey) return true;
  return false;
}

// --- OAuth 2.0 support (required for Claude.ai MCP HTTP connector) ---

// Short-lived authorization codes: code → { redirectUri, codeChallenge, expiry }
const pendingCodes = new Map<string, { redirectUri: string; codeChallenge: string; expiry: number }>();

function getServerBaseUrl(req: IncomingMessage): string {
  if (process.env.SERVER_URL) return process.env.SERVER_URL.replace(/\/$/, '');
  const proto = (req.headers['x-forwarded-proto'] as string | undefined) ?? 'https';
  const host = (req.headers['x-forwarded-host'] as string | undefined) ?? req.headers.host ?? 'localhost:3000';
  return `${proto}://${host}`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function readFormBody(req: IncomingMessage): Promise<URLSearchParams> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(new URLSearchParams(Buffer.concat(chunks).toString('utf-8'))));
    req.on('error', reject);
  });
}

/**
 * Handle OAuth 2.0 discovery and authorization endpoints.
 * Returns true if the request was handled (caller should not continue processing).
 * Only active when MCP_API_KEY is configured.
 */
async function handleOAuthRequest(
  pathname: string,
  req: IncomingMessage,
  res: ServerResponse,
  apiKey: string,
): Promise<boolean> {
  const baseUrl = getServerBaseUrl(req);

  // RFC 9728 — OAuth 2.0 Protected Resource Metadata
  if (pathname === '/.well-known/oauth-protected-resource/mcp') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(
      JSON.stringify({
        resource: `${baseUrl}/mcp`,
        authorization_servers: [baseUrl],
        scopes_supported: ['mcp'],
      }),
    );
    return true;
  }

  // RFC 8414 — OAuth 2.0 Authorization Server Metadata
  if (pathname === '/.well-known/oauth-authorization-server') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(
      JSON.stringify({
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/authorize`,
        token_endpoint: `${baseUrl}/token`,
        registration_endpoint: `${baseUrl}/register`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['none'],
        scopes_supported: ['mcp'],
      }),
    );
    return true;
  }

  // Authorization endpoint — show API-key entry form (GET) or process it (POST)
  if (pathname === '/authorize') {
    if (req.method === 'GET') {
      const reqUrl = new URL(req.url ?? '/', `${baseUrl}`);
      const redirectUri = reqUrl.searchParams.get('redirect_uri') ?? '';
      const state = reqUrl.searchParams.get('state') ?? '';
      const codeChallenge = reqUrl.searchParams.get('code_challenge') ?? '';
      const method = reqUrl.searchParams.get('code_challenge_method') ?? 'S256';

      if (method !== 'S256') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'invalid_request',
            error_description: 'Only S256 code_challenge_method is supported',
          }),
        );
        return true;
      }

      const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Bring! MCP — Authorize</title>
<style>*{box-sizing:border-box}body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f5f5}.card{background:#fff;border-radius:8px;padding:32px;max-width:360px;width:100%;box-shadow:0 2px 8px rgba(0,0,0,.12)}h2{margin:0 0 8px;font-size:1.25rem}p{margin:0 0 20px;color:#555;font-size:.95rem}input{display:block;width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:6px;margin-bottom:16px;font-size:1rem}button{display:block;width:100%;padding:10px;background:#16a34a;color:#fff;border:none;border-radius:6px;font-size:1rem;cursor:pointer;font-weight:600}button:hover{background:#15803d}</style>
</head>
<body><div class="card">
<h2>Bring! MCP Server</h2>
<p>Enter your API key to authorize access.</p>
<form method="POST">
  <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
  <input type="hidden" name="state" value="${escapeHtml(state)}">
  <input type="hidden" name="code_challenge" value="${escapeHtml(codeChallenge)}">
  <input type="password" name="api_key" placeholder="API key" required autofocus>
  <button type="submit">Authorize</button>
</form>
</div></body></html>`;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return true;
    }

    if (req.method === 'POST') {
      const params = await readFormBody(req);
      const submittedKey = params.get('api_key') ?? '';
      const redirectUri = params.get('redirect_uri') ?? '';
      const state = params.get('state') ?? '';
      const codeChallenge = params.get('code_challenge') ?? '';

      if (submittedKey !== apiKey) {
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(
          '<!DOCTYPE html><html><head><title>Unauthorized</title></head>' +
            '<body><p>Invalid API key. <a href="javascript:history.back()">Try again</a>.</p></body></html>',
        );
        return true;
      }

      const code = crypto.randomBytes(32).toString('base64url');
      pendingCodes.set(code, {
        redirectUri,
        codeChallenge,
        expiry: Date.now() + 5 * 60 * 1000, // 5-minute window
      });

      const callback = new URL(redirectUri);
      callback.searchParams.set('code', code);
      if (state) callback.searchParams.set('state', state);

      res.writeHead(302, { Location: callback.toString() });
      res.end();
      return true;
    }
  }

  // Dynamic Client Registration (RFC 7591) — required by MCP spec
  if (pathname === '/register' && req.method === 'POST') {
    const body = (await readRequestBody(req)) as Record<string, unknown> | undefined;
    const clientId = crypto.randomUUID();
    res.writeHead(201, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(
      JSON.stringify({
        client_id: clientId,
        client_name: (body?.client_name as string) ?? 'MCP Client',
        redirect_uris: (body?.redirect_uris as string[]) ?? [],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    );
    return true;
  }

  // Token endpoint — exchange authorization code for access token
  if (pathname === '/token' && req.method === 'POST') {
    const params = await readFormBody(req);
    const grantType = params.get('grant_type');
    const code = params.get('code') ?? '';
    const codeVerifier = params.get('code_verifier') ?? '';
    const redirectUri = params.get('redirect_uri') ?? '';

    if (grantType !== 'authorization_code') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unsupported_grant_type' }));
      return true;
    }

    const pending = pendingCodes.get(code);
    if (!pending || Date.now() > pending.expiry) {
      pendingCodes.delete(code);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' }));
      return true;
    }

    if (pending.redirectUri !== redirectUri) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' }));
      return true;
    }

    if (pending.codeChallenge) {
      const computed = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
      if (computed !== pending.codeChallenge) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }));
        return true;
      }
    }

    pendingCodes.delete(code);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ access_token: apiKey, token_type: 'bearer' }));
    return true;
  }

  return false;
}

// Start the server
async function main() {
  if (!process.env.MAIL || !process.env.PW) {
    console.error(
      'Missing MAIL or PW environment variables. Please create a .env file with your Bring credentials (e.g., MAIL=your_email@example.com\nPW=your_password).',
    );
    process.exit(1);
    return;
  }

  const bc = new BringClient(); // Instantiated after env check

  // Register tools from modules
  registerListTools(server, bc);
  registerItemTools(server, bc);
  registerUserTools(server, bc);
  registerCatalogTools(server, bc);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless mode: no session management
  });
  await server.connect(transport);

  const PORT = parseInt(process.env.PORT ?? '3000', 10);
  const API_KEY = process.env.MCP_API_KEY; // Optional bearer token / API key
  const ALLOWED_ORIGIN = process.env.CORS_ORIGIN ?? '*'; // e.g. "https://claude.ai"

  const httpServer = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const origin = req.headers['origin'] as string | undefined;
    setCorsHeaders(res, origin, ALLOWED_ORIGIN);

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Health check endpoint used by Railway and other platforms
    const pathname = req.url?.split('?')[0];
    if (pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }

    // OAuth 2.0 discovery and authorization endpoints (only when API_KEY is configured)
    if (API_KEY && (await handleOAuthRequest(pathname!, req, res, API_KEY))) {
      return;
    }

    // Only serve MCP traffic at /mcp
    if (pathname !== '/mcp') {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }

    // Authenticate when MCP_API_KEY is configured
    if (!isAuthenticated(req, API_KEY)) {
      const baseUrl = getServerBaseUrl(req);
      res.writeHead(401, {
        'WWW-Authenticate': `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource/mcp"`,
      });
      res.end('Unauthorized');
      return;
    }

    try {
      if (req.method === 'POST') {
        const body = await readRequestBody(req);
        await transport.handleRequest(req, res, body);
      } else {
        // GET (SSE streaming) and DELETE (session close)
        await transport.handleRequest(req, res);
      }
    } catch (err) {
      console.error('Request handling error:', err);
      if (!res.headersSent) {
        res.writeHead(500);
        res.end('Internal Server Error');
      }
    }
  });

  console.error(`MCP server for Bring! API is running on HTTP port ${PORT}`);
  httpServer.listen(PORT);
}

main().catch((e) => {
  console.error('Fatal error starting MCP server:', e);
  process.exit(1);
});
