# Prowler MCP Proxy

Proxy server that forwards requests from your Cloudflare Worker to Prowler MCP. Prowler returns 403 for requests from Cloudflare IPs; this proxy runs on Railway/Render/etc. and uses different IPs that Prowler accepts.

## Setup

### 1. Install dependencies

```bash
cd prowler-proxy
npm install
```

### 2. Set environment variables

Create a `.env` file (or set in your hosting platform):

```
PROWLER_API_KEY=your-prowler-cloud-api-key
PROXY_SECRET=your-random-secret  # e.g. run: openssl rand -hex 32
PORT=3000
```

### 3. Deploy

**Railway:**
1. Create account at [railway.app](https://railway.app)
2. New Project → Deploy from GitHub (or `railway init` + `railway up`)
3. Add env vars: `PROWLER_API_KEY`, `PROXY_SECRET`
4. Copy the public URL (e.g. `https://prowler-proxy-production-xxxx.up.railway.app`)

**Render:**
1. Create account at [render.com](https://render.com)
2. New → Web Service → Connect repo
3. Build: `npm install`, Start: `npm start`
4. Add env vars: `PROWLER_API_KEY`, `PROXY_SECRET`
5. Copy the service URL

### 4. Configure your Cloudflare Worker

```bash
cd ../mcp-cflare-dns
wrangler secret put PROWLER_MCP_URL   # Enter: https://YOUR-PROXY-URL
wrangler secret put PROXY_SECRET      # Same value as on the proxy
```

Then deploy: `npm run deploy`

## Flow

```
Cursor/Claude → Cloudflare Worker → Prowler Proxy → Prowler MCP → AWS
                    (X-Proxy-Secret)    (adds API key)
```

- Worker sends `X-Proxy-Secret` to authenticate
- Proxy adds `Authorization: Bearer PROWLER_API_KEY` when forwarding to Prowler
- Prowler API key stays only on the proxy, not in the Worker
