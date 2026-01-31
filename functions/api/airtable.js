// Cloudflare Pages Function - Secure Airtable Proxy
// Rate limit: 1000 req/min per IP using Cloudflare KV (optional) or in-memory

const ALLOWED_ORIGINS = [
    'https://prioai.ca',
    'https://www.prioai.ca',
    'https://dashboard.prioai.ca',
    'http://localhost:3000',
    'http://localhost:8788',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:8788'
];

const ALLOWED_BASE = 'applOjDjhH0RqLtBH';

const ALLOWED_TABLES = [
    'Admin%20Settings',
    'Admin Settings',
    'Team%20Members',
    'Team Members',
    'tblMptC862PyL7Znw',  // Clients
    'tblvB5OpG0b5mVix3',  // Calls
    'tblLpN4wceakfNFpq'   // Leads
];

// In-memory rate limiting (resets on cold start, use KV for persistence)
const rateLimitMap = new Map();
const RATE_LIMIT = 1000;
const RATE_WINDOW = 60 * 1000; // 1 minute

function checkRateLimit(ip) {
    const now = Date.now();
    const record = rateLimitMap.get(ip);

    if (!record || now - record.windowStart > RATE_WINDOW) {
        rateLimitMap.set(ip, { windowStart: now, count: 1 });
        return true;
    }

    if (record.count >= RATE_LIMIT) {
        return false;
    }

    record.count++;
    return true;
}

function getCorsHeaders(origin) {
    const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
    return {
        'Access-Control-Allow-Origin': allowedOrigin,
        'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400'
    };
}

function validatePath(path) {
    if (!path) return { valid: false, error: 'Missing path parameter' };

    // Path should start with base ID
    if (!path.startsWith(ALLOWED_BASE)) {
        return { valid: false, error: 'Invalid base ID' };
    }

    // Extract table from path (format: baseId/tableName or baseId/tableName/recordId)
    const pathParts = path.replace(ALLOWED_BASE + '/', '').split('/');
    const table = pathParts[0];

    if (!table) {
        return { valid: false, error: 'Missing table name' };
    }

    // Check if table is in allowed list
    const decodedTable = decodeURIComponent(table);
    if (!ALLOWED_TABLES.includes(table) && !ALLOWED_TABLES.includes(decodedTable)) {
        return { valid: false, error: 'Table not allowed' };
    }

    return { valid: true };
}

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = getCorsHeaders(origin);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders });
    }

    // Check origin for non-GET requests
    if (request.method !== 'GET' && !ALLOWED_ORIGINS.includes(origin)) {
        return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
            status: 403,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }

    // Rate limiting
    const clientIP = request.headers.get('CF-Connecting-IP') ||
                     request.headers.get('X-Forwarded-For')?.split(',')[0] ||
                     'unknown';

    if (!checkRateLimit(clientIP)) {
        return new Response(JSON.stringify({ error: 'Rate limit exceeded. Max 1000 requests per minute.' }), {
            status: 429,
            headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Retry-After': '60' }
        });
    }

    // Get Airtable token from environment
    const airtableToken = env.AIRTABLE_TOKEN;
    if (!airtableToken) {
        return new Response(JSON.stringify({ error: 'Server configuration error' }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }

    // Get and validate path
    const path = url.searchParams.get('path');
    const validation = validatePath(path);

    if (!validation.valid) {
        return new Response(JSON.stringify({ error: validation.error }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }

    // Build Airtable URL with query params
    const airtableUrl = new URL(`https://api.airtable.com/v0/${path}`);

    // Forward allowed query parameters
    const allowedParams = ['pageSize', 'offset', 'sort[0][field]', 'sort[0][direction]', 'filterByFormula', 'view'];
    for (const [key, value] of url.searchParams) {
        if (key !== 'path' && (allowedParams.includes(key) || key.startsWith('sort['))) {
            airtableUrl.searchParams.set(key, value);
        }
    }

    // Prepare fetch options
    const fetchOptions = {
        method: request.method,
        headers: {
            'Authorization': `Bearer ${airtableToken}`,
            'Content-Type': 'application/json'
        }
    };

    // Include body for POST/PATCH/PUT requests
    if (['POST', 'PATCH', 'PUT'].includes(request.method)) {
        try {
            const body = await request.text();
            if (body) {
                fetchOptions.body = body;
            }
        } catch (e) {
            // No body, continue
        }
    }

    try {
        const response = await fetch(airtableUrl.toString(), fetchOptions);
        const data = await response.text();

        return new Response(data, {
            status: response.status,
            headers: {
                ...corsHeaders,
                'Content-Type': 'application/json'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: 'Failed to fetch from Airtable' }), {
            status: 502,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}
