/**
 * Prowler MCP Proxy
 *
 * Sits between Cloudflare Worker and Prowler MCP.
 * Prowler blocks requests from Cloudflare IPs (403); this proxy runs elsewhere
 * and forwards requests with the Prowler API key.
 *
 * Env vars:
 *   PROWLER_API_KEY - Your Prowler Cloud/App API key
 *   PROXY_SECRET    - Shared secret; Worker must send X-Proxy-Secret with this value
 *   PORT            - Server port (default 3000)
 */

const express = require("express");
const PROWLER_MCP_URL = "https://mcp.prowler.com/mcp";

const app = express();
app.use(express.json({ limit: "10mb" }));

const PROWLER_API_KEY = process.env.PROWLER_API_KEY;
const PROXY_SECRET = process.env.PROXY_SECRET;
const PORT = process.env.PORT || 3000;

if (!PROWLER_API_KEY || !PROXY_SECRET) {
  console.error("Missing PROWLER_API_KEY or PROXY_SECRET. Set both env vars.");
  process.exit(1);
}

app.post("/", async (req, res) => {
  const secret = req.headers["x-proxy-secret"];
  if (secret !== PROXY_SECRET) {
    return res.status(401).json({
      jsonrpc: "2.0",
      id: req.body?.id ?? null,
      error: { code: -32001, message: "Invalid or missing X-Proxy-Secret" },
    });
  }

  try {
    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "User-Agent": "prowler-proxy/1.0 (MCP-Client)",
      Authorization: `Bearer ${PROWLER_API_KEY}`,
    };
    if (req.headers["mcp-session-id"]) headers["MCP-Session-Id"] = req.headers["mcp-session-id"];
    if (req.headers["mcp-protocol-version"]) headers["MCP-Protocol-Version"] = req.headers["mcp-protocol-version"];

    const prowlerRes = await fetch(PROWLER_MCP_URL, {
      method: "POST",
      headers,
      body: JSON.stringify(req.body),
    });

    const text = await prowlerRes.text();
    res.status(prowlerRes.status).set("Content-Type", "application/json");
    prowlerRes.headers.forEach((value, key) => {
      if (key.toLowerCase().startsWith("mcp")) res.set(key, value);
    });
    res.send(text);
  } catch (err) {
    console.error("[Prowler proxy error]", err);
    res.status(502).json({
      jsonrpc: "2.0",
      id: req.body?.id ?? null,
      error: { code: -32603, message: `Proxy error: ${err.message}` },
    });
  }
});

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "prowler-proxy" });
});

app.get("/debug-init", async (req, res) => {
  try {
    const prowlerRes = await fetch(PROWLER_MCP_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "User-Agent": "prowler-proxy/1.0 (MCP-Client)",
        Authorization: `Bearer ${PROWLER_API_KEY}`,
        "MCP-Protocol-Version": "2025-11-25",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "debug", version: "1.0" },
        },
      }),
    });
    const text = await prowlerRes.text();
    const headers = {};
    prowlerRes.headers.forEach((v, k) => { headers[k] = v; });
    res.json({ status: prowlerRes.status, headers, body: text.slice(0, 500) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Prowler proxy listening on port ${PORT}`);
});
