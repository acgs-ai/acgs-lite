import assert from "node:assert/strict";
import test from "node:test";

import worker, {
  SECURITY_HEADERS,
  applyResponseHeaders,
  resolveCacheControl,
} from "../worker.js";

function makeEnv(handler) {
  return {
    ASSETS: {
      async fetch(request) {
        return handler(request);
      },
    },
  };
}

test("GET / redirects permanently to /docs/ preserving query string and security headers", async () => {
  const req = new Request("https://acgs.ai/?q=maci");
  const res = await worker.fetch(req, makeEnv(() => {
    throw new Error("ASSETS.fetch should not be called on root redirect");
  }));

  assert.equal(res.status, 308);
  assert.equal(res.headers.get("Location"), "https://acgs.ai/docs/?q=maci");
  assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(res.headers.get("X-Frame-Options"), "DENY");
  assert.ok(res.headers.get("Content-Security-Policy").includes("frame-ancestors 'none'"));
});

test("GET /docs redirects permanently to /docs/", async () => {
  const req = new Request("https://acgs.ai/docs");
  const res = await worker.fetch(req, makeEnv(() => {
    throw new Error("ASSETS.fetch should not be called on /docs redirect");
  }));

  assert.equal(res.status, 308);
  assert.equal(res.headers.get("Location"), "https://acgs.ai/docs/");
});

test("non-GET/HEAD methods return 405 with Allow and security headers", async () => {
  for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
    const req = new Request("https://acgs.ai/docs/", { method });
    const res = await worker.fetch(req, makeEnv(() => {
      throw new Error("ASSETS.fetch should not be called for disallowed methods");
    }));

    assert.equal(res.status, 405);
    assert.equal(res.headers.get("Allow"), "GET, HEAD");
    assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
    assert.equal(res.headers.get("Cache-Control"), "public, max-age=60");
  }
});

test("GET and HEAD HTML pages receive security headers and bfcache-safe caching", async () => {
  for (const method of ["GET", "HEAD"]) {
    const req = new Request("https://acgs.ai/docs/quickstart/", { method });
    const res = await worker.fetch(
      req,
      makeEnv(() => new Response(method === "HEAD" ? null : "<h1>Docs</h1>", {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      })),
    );

    assert.equal(res.status, 200);
    for (const [name, expected] of Object.entries(SECURITY_HEADERS)) {
      assert.equal(res.headers.get(name), expected, `header ${name} mismatch`);
    }
    const cc = res.headers.get("Cache-Control");
    assert.equal(cc, "public, max-age=300, stale-while-revalidate=86400");
    assert.ok(!cc.includes("no-store"), "HTML docs must not use no-store (breaks bfcache)");
  }
});

test("content-hashed MkDocs bundles get immutable long-lived Cache-Control", () => {
  assert.equal(
    resolveCacheControl("/docs/assets/javascripts/bundle.79ae519e.min.js", 200),
    "public, max-age=31536000, immutable",
  );
  assert.equal(
    resolveCacheControl("/docs/assets/stylesheets/main.484c7ddc.min.css", 200),
    "public, max-age=31536000, immutable",
  );
  assert.equal(
    resolveCacheControl("/docs/assets/javascripts/workers/search.2c215733.min.js", 200),
    "public, max-age=31536000, immutable",
  );
});

test("unhashed static assets and search index get 1h SWR caching while 404s get short TTL", () => {
  assert.equal(
    resolveCacheControl("/docs/assets/_mkdocstrings.css", 200),
    "public, max-age=3600, stale-while-revalidate=86400",
  );
  assert.equal(
    resolveCacheControl("/docs/search/search_index.json", 200),
    "public, max-age=3600, stale-while-revalidate=86400",
  );
  assert.equal(
    resolveCacheControl("/docs/sitemap.xml", 200),
    "public, max-age=3600, stale-while-revalidate=86400",
  );
  assert.equal(
    resolveCacheControl("/docs/assets/javascripts/bundle.79ae519e.min.js", 404),
    "public, max-age=60",
  );
});

test("applyResponseHeaders preserves explicit upstream Cache-Control and security headers", () => {
  const upstream = new Response("ok", {
    status: 200,
    headers: {
      "Cache-Control": "public, max-age=120",
      "X-Frame-Options": "SAMEORIGIN",
    },
  });
  const out = applyResponseHeaders(upstream, "/docs/index.html");

  assert.equal(out.headers.get("Cache-Control"), "public, max-age=120");
  assert.equal(out.headers.get("X-Frame-Options"), "SAMEORIGIN");
  assert.equal(out.headers.get("X-Content-Type-Options"), "nosniff");
});
