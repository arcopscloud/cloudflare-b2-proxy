import { AwsClient } from 'aws4fetch';

// Global CORS headers for browser compatibility
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': '*',
};

const unsignedError = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Unauthenticated requests are not allowed for private paths.</Message>
</Error>`;

const validationError = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error>
    <Type>Sender</Type>
    <Code>SignatureDoesNotMatch</Code>
    <Message>Signature validation failed.</Message>
  </Error>
</ErrorResponse>`;

// Filter out Cloudflare and hop-by-hop headers that break B2 signatures
function filterHeaders(headers) {
  const STRIP = ['x-forwarded-proto', 'x-real-ip', 'host', 'cf-ray', 'cf-connecting-ip', 'cf-ipcountry', 'cf-visitor'];
  const filtered = new Headers();
  for (const [k, v] of headers.entries()) {
    const lower = k.toLowerCase();
    if (!STRIP.includes(lower) && !lower.startsWith('cf-')) {
      filtered.set(k, v);
    }
  }
  return filtered;
}

// AWS SigV4 verification for Private S3 API calls
async function verifySignature(request, aws, expectedKey) {
  const authorization = request.headers.get('Authorization');
  if (!authorization) throw new Error('MISSING');

  const re = /^AWS4-HMAC-SHA256 Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=(.+)$/;
  const match = authorization.match(re);
  if (!match) throw new Error('INVALID');

  const [ , credential, signedHeaders, signature] = match;
  const keyId = credential.split('/')[0];
  if (keyId !== expectedKey) throw new Error('INVALID');

  const datetime = request.headers.get('x-amz-date');
  const headersToSign = {};
  signedHeaders.split(';').forEach((k) => {
    headersToSign[k] = request.headers.get(k);
  });

  const signedRequest = await aws.sign(request.url, {
    method: request.method,
    headers: headersToSign,
    body: request.method !== 'GET' && request.method !== 'HEAD' ? request.clone().body : null,
    aws: { datetime, allHeaders: true },
  });

  const signedMatch = signedRequest.headers.get('Authorization').match(re);
  if (!signedMatch || signature !== signedMatch[3]) {
    throw new Error('INVALID');
  }
}

export default {
  async fetch(request, env, ctx) {
    // 1. CORS Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const pathname = url.pathname;

    // 2. Health check for root URL
    if (pathname === '/' || pathname === '') {
      return new Response(JSON.stringify({ status: 'online', service: 'BuckStream S3 Broker', region: 'us-east' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }

    // 3. Clean endpoint & auto-detect region (e.g. s3.us-east-005.backblazeb2.com)
    const rawEndpoint = (env.AWS_S3_ENDPOINT || 's3.us-east-005.backblazeb2.com')
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
      .trim();

    const matchRegion = rawEndpoint.match(/^s3\.([a-zA-Z0-9-]+)\.backblazeb2\.com$/);
    const region = matchRegion ? matchRegion[1] : 'us-east-1';

    const aws = new AwsClient({
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
      service: 's3',
      region: region,
    });

    // 4. Check if request is a Public CDN route (/public/* or /<bucket>/public/*)
    const isPublicRoute =
      (request.method === 'GET' || request.method === 'HEAD') &&
      (pathname.startsWith('/public/') || pathname.includes('/public/'));

    // Check Cloudflare Edge Cache for Public Downloads
    const cache = caches.default;
    if (isPublicRoute) {
      const cached = await cache.match(request);
      if (cached) return cached;
    }

    // 5. Build Upstream B2 URL
    const upstreamUrl = new URL(request.url);
    upstreamUrl.hostname = rawEndpoint;

    // If request is directly /public/... and DEFAULT_BUCKET is provided, route into bucket
    if (pathname.startsWith('/public/') && env.DEFAULT_BUCKET) {
      upstreamUrl.pathname = `/${env.DEFAULT_BUCKET}${pathname}`;
    }

    // 6. Enforce AWS SigV4 security for private endpoints
    if (!isPublicRoute) {
      try {
        await verifySignature(request, aws, env.AWS_ACCESS_KEY_ID);
      } catch (err) {
        return new Response(err.message === 'MISSING' ? unsignedError : validationError, {
          status: 403,
          headers: { 'Content-Type': 'application/xml', ...corsHeaders },
        });
      }
    }

    // 7. Filter headers and sign outgoing request to B2
    const outgoingHeaders = filterHeaders(request.headers);
    const signedRequest = await aws.sign(upstreamUrl.toString(), {
      method: request.method,
      headers: outgoingHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : null,
    });

    // 8. Fetch from Backblaze B2 (Bandwidth Alliance: $0 Egress)
    let response;
    try {
      response = await fetch(signedRequest);
    } catch (fetchErr) {
      return new Response(JSON.stringify({ error: 'Failed to reach upstream B2', details: fetchErr.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }

    // 9. Reconstruct Response with CORS headers
    response = new Response(response.body, response);
    for (const [k, v] of Object.entries(corsHeaders)) {
      response.headers.set(k, v);
    }

    // 10. Cache ONLY successful 200 responses for public routes (avoid 206 Partial Content crash)
    if (isPublicRoute && response.status === 200) {
      response.headers.set('Cache-Control', 'public, max-age=604800, s-maxage=604800');
      try {
        ctx.waitUntil(cache.put(request, response.clone()));
      } catch (_) {}
    }

    // 11. Async Webhook Trigger (Only if configured)
    if (env.WEBHOOK_URL && env.WEBHOOK_URL.startsWith('http')) {
      ctx.waitUntil(
        fetch(env.WEBHOOK_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            method: request.method,
            path: pathname,
            status: response.status,
            isPublic: isPublicRoute,
            contentLength: request.headers.get('content-length'),
            timestamp: new Date().toISOString(),
          }),
        }).catch(() => {})
      );
    }

    return response;
  },
};
