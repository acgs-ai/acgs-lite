/**
 * Cloudflare Worker serving the static ACGS-Lite MkDocs documentation site (`./site/docs`).
 *
 * Applies preventative security headers (HSTS, CSP, X-Content-Type-Options,
 * X-Frame-Options, COOP, CORP, Referrer-Policy, Permissions-Policy) and
 * asset-aware Cache-Control policies without breaking bfcache.
 */

const HASHED_ASSET_RE = /\.[0-9a-f]{8}\.min\.(?:js|css)$/i;
const STATIC_ASSET_RE =
  /^\/docs\/(?:assets\/|search\/search_index\.json$|sitemap\.xml(?:\.gz)?$|objects\.inv$)/i;

const DOCS_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: https:",
  "connect-src 'self' https://api.github.com",
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join("; ");

export const SECURITY_HEADERS = Object.freeze({
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
  "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": DOCS_CSP,
});

/**
 * Compute Cache-Control for a docs response without disabling bfcache (`no-store`).
 */
export function resolveCacheControl(pathname, status) {
  if (status >= 400) {
    return "public, max-age=60";
  }
  if (HASHED_ASSET_RE.test(pathname)) {
    return "public, max-age=31536000, immutable";
  }
  if (STATIC_ASSET_RE.test(pathname)) {
    return "public, max-age=3600, stale-while-revalidate=86400";
  }
  return "public, max-age=300, stale-while-revalidate=86400";
}

/**
 * Clone a Response with security headers and asset-appropriate caching attached.
 */
export function applyResponseHeaders(response, pathname) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(name)) {
      headers.set(name, value);
    }
  }
  if (!headers.has("Cache-Control")) {
    headers.set("Cache-Control", resolveCacheControl(pathname, response.status));
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env, ctx) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return applyResponseHeaders(
        new Response("Method Not Allowed", {
          status: 405,
          headers: {
            Allow: "GET, HEAD",
            "Content-Type": "text/plain; charset=utf-8",
          },
        }),
        "/",
      );
    }

    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "/docs") {
      const target = new URL(`/docs/${url.search}`, url.origin);
      return applyResponseHeaders(
        new Response(null, {
          status: 308,
          headers: {
            Location: target.toString(),
            "Cache-Control": "public, max-age=3600",
          },
        }),
        url.pathname,
      );
    }

    const response = await env.ASSETS.fetch(request);
    return applyResponseHeaders(response, url.pathname);
  },
};
