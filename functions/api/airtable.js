// Cloudflare Pages Function - Airtable API Proxy
// Handles all Airtable requests securely with rate limiting and validation

// Allowed Airtable bases and tables
const ALLOWED_PATHS = {
    bases: ['appXXXXXXXXXXXXXX'], // Replace with your actual base ID
    tables: ['Clients', 'Calls', 'Leads', 'Costs', 'Revenue', 'Settings']
};

// CORS allowed origins
const ALLOWED_ORIGINS = [
    'https://prioai.ca',
    'https://dashboard.prioai.ca',
    'https://www.prioai.ca',
    'http://localhost:3000',
    'http://localhost:8788',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:8788'
];

// Rate limiting store (in-memory, resets on cold start)
const rateLimitStore = new Map();
const RATE_LIMIT = 1000; // requests per minute
const RATE_WINDOW = 60000; // 1 minute in ms

function getRateLimitKey(request) {
    return request.headers.get('CF-Connecting-IP') ||
           request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
           'unknown';
}

function checkRateLimit(ip) {
    const now = Date.now();
    const record = rateLimitStore.get(ip);

    if (!record || now - record.timestamp > RATE_WINDOW) {
        rateLimitStore.set(ip, { count: 1, timestamp: now });
        return { allowed: true, remaining: RATE_LIMIT - 1 };
    }

    if (record.count >= RATE_LIMIT) {
        return { allowed: false, remaining: 0, resetAt: record.timestamp + RATE_WINDOW };
    }

    record.count++;
    return { allowed: true, remaining: RATE_LIMIT - record.count };
}

function getCorsHeaders(request) {
    const origin = request.headers.get('Origin');
    const headers = {
        'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Max-Age': '86400',
    };

    if (origin && ALLOWED_ORIGINS.includes(origin)) {
        headers['Access-Control-Allow-Origin'] = origin;
        headers['Access-Control-Allow-Credentials'] = 'true';
    }

    return headers;
}

function validatePath(path) {
    // Path format: /base_id/table_name or /base_id/table_name/record_id
    const parts = path.split('/').filter(Boolean);

    if (parts.length < 2 || parts.length > 3) {
        return { valid: false, error: 'Invalid path format' };
    }

    const [baseId, tableName] = parts;

    if (!ALLOWED_PATHS.bases.includes(baseId)) {
        return { valid: false, error: 'Base not allowed' };
    }

    if (!ALLOWED_PATHS.tables.includes(tableName)) {
        return { valid: false, error: 'Table not allowed' };
    }

    return { valid: true, baseId, tableName, recordId: parts[2] };
}

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: getCorsHeaders(request)
        });
    }

    // Check for Airtable token
    const airtableToken = env.AIRTABLE_TOKEN;
    if (!airtableToken) {
        return new Response(JSON.stringify({ error: 'Server configuration error' }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                ...getCorsHeaders(request)
            }
        });
    }

    // Rate limiting
    const clientIP = getRateLimitKey(request);
    const rateLimit = checkRateLimit(clientIP);

    if (!rateLimit.allowed) {
        return new Response(JSON.stringify({
            error: 'Rate limit exceeded',
            resetAt: rateLimit.resetAt
        }), {
            status: 429,
            headers: {
                'Content-Type': 'application/json',
                'X-RateLimit-Limit': RATE_LIMIT.toString(),
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': rateLimit.resetAt.toString(),
                'Retry-After': Math.ceil((rateLimit.resetAt - Date.now()) / 1000).toString(),
                ...getCorsHeaders(request)
            }
        });
    }

    // Extract and validate path
    // URL format: /api/airtable/BASE_ID/TABLE_NAME[/RECORD_ID]
    const pathMatch = url.pathname.match(/^\/api\/airtable\/(.+)$/);
    if (!pathMatch) {
        return new Response(JSON.stringify({ error: 'Invalid endpoint' }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                ...getCorsHeaders(request)
            }
        });
    }

    const airtablePath = pathMatch[1];
    const validation = validatePath(airtablePath);

    if (!validation.valid) {
        return new Response(JSON.stringify({ error: validation.error }), {
            status: 403,
            headers: {
                'Content-Type': 'application/json',
                ...getCorsHeaders(request)
            }
        });
    }

    // Build Airtable API URL
    let airtableUrl = `https://api.airtable.com/v0/${validation.baseId}/${encodeURIComponent(validation.tableName)}`;
    if (validation.recordId) {
        airtableUrl += `/${validation.recordId}`;
    }

    // Pass through query parameters (for filtering, sorting, etc.)
    if (url.search) {
        airtableUrl += url.search;
    }

    // Prepare request to Airtable
    const airtableHeaders = {
        'Authorization': `Bearer ${airtableToken}`,
        'Content-Type': 'application/json'
    };

    const fetchOptions = {
        method: request.method,
        headers: airtableHeaders
    };

    // Include body for POST/PATCH/PUT requests
    if (['POST', 'PATCH', 'PUT'].includes(request.method)) {
        try {
            const body = await request.json();
            fetchOptions.body = JSON.stringify(body);
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    ...getCorsHeaders(request)
                }
            });
        }
    }

    // Make request to Airtable
    try {
        const airtableResponse = await fetch(airtableUrl, fetchOptions);
        const data = await airtableResponse.json();

        return new Response(JSON.stringify(data), {
            status: airtableResponse.status,
            headers: {
                'Content-Type': 'application/json',
                'X-RateLimit-Limit': RATE_LIMIT.toString(),
                'X-RateLimit-Remaining': rateLimit.remaining.toString(),
                ...getCorsHeaders(request)
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            error: 'Failed to fetch from Airtable',
            details: error.message
        }), {
            status: 502,
            headers: {
                'Content-Type': 'application/json',
                ...getCorsHeaders(request)
            }
        });
    }
}
