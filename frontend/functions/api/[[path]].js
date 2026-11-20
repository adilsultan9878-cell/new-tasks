/**
 * Cloudflare Pages Function: proxies /api/* to the backend (e.g. Render).
 *
 * Why: the console and the API then share one origin, so the HttpOnly refresh cookie is a
 * first-party cookie (SameSite=Lax) and is not blocked by browsers' third-party-cookie
 * protections. Configure the API_ORIGIN environment variable in the Pages project, e.g.
 * https://sentinel-x-api.onrender.com
 */
export async function onRequest({ request, env }) {
  if (!env.API_ORIGIN) {
    return new Response(JSON.stringify({ error: { code: 'proxy_not_configured', message: 'API_ORIGIN is not set' } }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    })
  }
  const incoming = new URL(request.url)
  const target = new URL(incoming.pathname + incoming.search, env.API_ORIGIN)

  // WebSocket upgrades (/api/v1/ws) are passed straight through; the API authenticates the
  // first message and checks the Origin header against CORS_ORIGINS.
  if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
    return fetch(new Request(target.toString(), request))
  }

  const headers = new Headers(request.headers)
  headers.delete('host')
  // Replace any client-supplied forwarding header with the address Cloudflare observed.
  const clientIp = request.headers.get('CF-Connecting-IP')
  if (clientIp) headers.set('X-Forwarded-For', clientIp)
  else headers.delete('X-Forwarded-For')
  headers.set('X-Forwarded-Proto', 'https')
  headers.set('X-Forwarded-Host', incoming.host)

  const hasBody = !['GET', 'HEAD'].includes(request.method)
  const upstream = await fetch(target.toString(), {
    method: request.method,
    headers,
    // Buffered: API payloads are small JSON, and this is portable across runtimes.
    body: hasBody ? await request.arrayBuffer() : undefined,
    redirect: 'manual',
  })
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: upstream.headers })
}
