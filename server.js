import express from "express";
import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual
} from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

const PORT = Number(process.env.PORT || 3000);
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;
const OAUTH_SIGNING_SECRET = process.env.OAUTH_SIGNING_SECRET;
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/+$/, "");

if (!GITHUB_TOKEN || !MCP_AUTH_TOKEN || !OAUTH_SIGNING_SECRET || !PUBLIC_URL) {
  throw new Error("Set GITHUB_TOKEN, MCP_AUTH_TOKEN, OAUTH_SIGNING_SECRET, and PUBLIC_URL");
}

const ISSUER = PUBLIC_URL;
const RESOURCE = PUBLIC_URL + "/mcp";
const AUTH_CODES = new Map();

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function sign(value) {
  return createHmac("sha256", OAUTH_SIGNING_SECRET)
    .update(value)
    .digest("base64url");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}

function signedToken(payload) {
  const body = b64url(JSON.stringify(payload));
  return body + "." + sign(body);
}

function readSignedToken(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2 || !safeEqual(sign(parts[0]), parts[1])) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function makeClientId(redirectUris, clientName) {
  const body = b64url(JSON.stringify({
    redirect_uris: redirectUris,
    client_name: String(clientName || "MCP client").slice(0, 100),
    issued_at: Date.now()
  }));
  return body + "." + sign("client:" + body);
}

function readClientId(clientId) {
  if (typeof clientId !== "string") return null;
  const parts = clientId.split(".");
  if (parts.length !== 2 || !safeEqual(sign("client:" + parts[0]), parts[1])) return null;
  try {
    const data = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (!Array.isArray(data.redirect_uris) || !data.redirect_uris.length) return null;
    return data;
  } catch {
    return null;
  }
}

function validRedirect(uri) {
  try {
    const parsed = new URL(uri);
    return parsed.protocol === "https:" ||
      (parsed.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname));
  } catch {
    return false;
  }
}

function sha256Base64Url(value) {
  return createHash("sha256").update(value).digest("base64url");
}

async function github(path, options = {}) {
  const response = await fetch("https://api.github.com" + path, {
    ...options,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: "Bearer " + GITHUB_TOKEN,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers
    }
  });
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; }
  catch { data = { message: text }; }
  if (!response.ok) throw new Error("GitHub API " + response.status + ": " + (data.message || text));
  return data;
}

function createServer() {
  const server = new McpServer({
    name: "github-claude-mcp",
    version: "1.0.0"
  });

  // Repository information
  server.tool(
    "github_repo_info",
    "Get repository information",
    {
      repo: z.string().describe("owner/repository")
    },
    async ({ repo }) => {
      const result = await github(`/repos/${repo}`);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            name: result.full_name,
            description: result.description,
            default_branch: result.default_branch,
            private: result.private,
            url: result.html_url
          }, null, 2)
        }]
      };
    }
  );

  // List files
  server.tool(
    "github_list_files",
    "List files and folders in a repository",
    {
      repo: z.string(),
      path: z.string().default(""),
      ref: z.string().optional()
    },
    async ({ repo, path, ref }) => {
      const query = ref
        ? `?ref=${encodeURIComponent(ref)}`
        : "";

      const result = await github(
        `/repos/${repo}/contents/${path}${query}`
      );

      const items = Array.isArray(result)
        ? result
        : [result];

      return {
        content: [{
          type: "text",
          text: JSON.stringify(
            items.map(item => ({
              name: item.name,
              path: item.path,
              type: item.type,
              sha: item.sha
            })),
            null,
            2
          )
        }]
      };
    }
  );

  // Read file
  server.tool(
    "github_read_file",
    "Read a text file from GitHub",
    {
      repo: z.string(),
      path: z.string(),
      ref: z.string().optional()
    },
    async ({ repo, path, ref }) => {
      const query = ref
        ? `?ref=${encodeURIComponent(ref)}`
        : "";

      const file = await github(
        `/repos/${repo}/contents/${path}${query}`
      );

      if (Array.isArray(file) || file.type !== "file") {
        throw new Error("Path is not a file");
      }

      if (file.encoding !== "base64") {
        throw new Error("Unsupported file encoding");
      }

      const content = Buffer.from(
        file.content.replace(/\n/g, ""),
        "base64"
      ).toString("utf8");

      return {
        content: [{
          type: "text",
          text: content
        }]
      };
    }
  );

  // Create or update file
  server.tool(
    "github_write_file",
    "Create or update a GitHub file. Provide sha when updating an existing file.",
    {
      repo: z.string(),
      path: z.string(),
      content: z.string(),
      message: z.string(),
      branch: z.string().optional(),
      sha: z.string().optional()
    },
    async ({
      repo,
      path,
      content,
      message,
      branch,
      sha
    }) => {
      const result = await github(
        `/repos/${repo}/contents/${path}`,
        {
          method: "PUT",
          body: JSON.stringify({
            message,
            content: Buffer.from(
              content,
              "utf8"
            ).toString("base64"),
            ...(branch ? { branch } : {}),
            ...(sha ? { sha } : {})
          })
        }
      );

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            path: result.content?.path,
            commit: result.commit?.sha,
            url: result.content?.html_url
          }, null, 2)
        }]
      };
    }
  );

  // Delete file
  server.tool(
    "github_delete_file",
    "Delete a file from GitHub",
    {
      repo: z.string(),
      path: z.string(),
      sha: z.string(),
      message: z.string(),
      branch: z.string().optional()
    },
    async ({ repo, path, sha, message, branch }) => {
      const result = await github(
        `/repos/${repo}/contents/${path}`,
        {
          method: "DELETE",
          body: JSON.stringify({
            message,
            sha,
            ...(branch ? { branch } : {})
          })
        }
      );

      return {
        content: [{
          type: "text",
          text: `Deleted ${path}. Commit: ${result.commit?.sha}`
        }]
      };
    }
  );

  // Create branch
  server.tool(
    "github_create_branch",
    "Create a branch from an existing branch",
    {
      repo: z.string(),
      branch: z.string(),
      from: z.string().optional()
    },
    async ({ repo, branch, from }) => {
      const repoInfo = await github(`/repos/${repo}`);
      const base = from || repoInfo.default_branch;

      const baseRef = await github(
        `/repos/${repo}/git/ref/heads/${encodeURIComponent(base).replaceAll("%2F", "/")}`
      );

      const result = await github(
        `/repos/${repo}/git/refs`,
        {
          method: "POST",
          body: JSON.stringify({
            ref: `refs/heads/${branch}`,
            sha: baseRef.object.sha
          })
        }
      );

      return {
        content: [{
          type: "text",
          text: `Created branch ${branch} at ${result.object.sha}`
        }]
      };
    }
  );

  // Create issue
  server.tool(
    "github_create_issue",
    "Create a GitHub issue",
    {
      repo: z.string(),
      title: z.string(),
      body: z.string().optional()
    },
    async ({ repo, title, body }) => {
      const result = await github(
        `/repos/${repo}/issues`,
        {
          method: "POST",
          body: JSON.stringify({
            title,
            ...(body ? { body } : {})
          })
        }
      );

      return {
        content: [{
          type: "text",
          text: `Created issue #${result.number}: ${result.html_url}`
        }]
      };
    }
  );

  return server;
}

// OAuth authorization-server metadata (RFC 8414)
app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: ISSUER + "/authorize",
    token_endpoint: ISSUER + "/token",
    registration_endpoint: ISSUER + "/register",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["github"]
  });
});

// Protected-resource metadata (RFC 9728)
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: RESOURCE,
    authorization_servers: [ISSUER],
    bearer_methods_supported: ["header"],
    scopes_supported: ["github"],
    resource_name: "GitHub Claude MCP"
  });
});

// Path-aware protected-resource metadata for the /mcp resource.
app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => {
  res.json({
    resource: RESOURCE,
    authorization_servers: [ISSUER],
    bearer_methods_supported: ["header"],
    scopes_supported: ["github"],
    resource_name: "GitHub Claude MCP"
  });
});

// Dynamic Client Registration (public clients with PKCE)
app.post("/register", (req, res) => {
  const redirectUris = req.body?.redirect_uris;
  if (!Array.isArray(redirectUris) || !redirectUris.length ||
      redirectUris.length > 20 ||
      !redirectUris.every(uri => typeof uri === "string" && validRedirect(uri))) {
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }
  if (req.body.token_endpoint_auth_method &&
      req.body.token_endpoint_auth_method !== "none") {
    return res.status(400).json({ error: "invalid_client_metadata" });
  }
  const clientId = makeClientId(redirectUris, req.body.client_name);
  res.status(201).json({
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    redirect_uris: redirectUris,
    client_name: req.body.client_name || "MCP client"
  });
});

// OAuth authorization endpoint. The owner approves access using MCP_AUTH_TOKEN.
app.get("/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, resource } = req.query;
  const client = readClientId(client_id);
  if (response_type !== "code" || !client ||
      !client.redirect_uris.includes(redirect_uri) ||
      code_challenge_method !== "S256" ||
      typeof code_challenge !== "string" ||
      (resource && resource !== RESOURCE)) {
    return res.status(400).send("Invalid OAuth authorization request");
  }
  const esc = value => String(value || "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[ch]);
  res.type("html").send(
    "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>" +
    "<title>Authorize GitHub MCP</title></head><body style='font:16px system-ui;max-width:520px;margin:40px auto;padding:0 18px'>" +
    "<h2>Authorize GitHub MCP</h2><p>Allow " + esc(client.client_name) +
    " to use the GitHub tools connected to this server?</p>" +
    "<form method='post' action='/authorize'>" +
    "<input type='hidden' name='client_id' value='" + esc(client_id) + "'>" +
    "<input type='hidden' name='redirect_uri' value='" + esc(redirect_uri) + "'>" +
    "<input type='hidden' name='state' value='" + esc(state) + "'>" +
    "<input type='hidden' name='code_challenge' value='" + esc(code_challenge) + "'>" +
    "<input type='hidden' name='resource' value='" + esc(resource || RESOURCE) + "'>" +
    "<label>Server owner approval token<br><input name='approval_token' type='password' required autocomplete='current-password' style='box-sizing:border-box;width:100%;padding:12px;margin:8px 0'></label>" +
    "<button type='submit' style='padding:10px 18px'>Authorize</button></form>" +
    "<p style='color:#666;font-size:13px'>This is the MCP_AUTH_TOKEN you set in Railway. It is not your GitHub token.</p></body></html>"
  );
});

app.post("/authorize", (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, resource, approval_token } = req.body || {};
  const client = readClientId(client_id);
  if (!client || !client.redirect_uris.includes(redirect_uri) ||
      !safeEqual(approval_token || "", MCP_AUTH_TOKEN)) {
    return res.status(401).send("Authorization denied. Check the approval token and try again.");
  }
  const code = randomBytes(32).toString("base64url");
  AUTH_CODES.set(code, {
    client_id,
    redirect_uri,
    code_challenge,
    resource: resource || RESOURCE,
    expires_at: Date.now() + 5 * 60 * 1000
  });
  const destination = new URL(redirect_uri);
  destination.searchParams.set("code", code);
  if (state) destination.searchParams.set("state", state);
  res.redirect(302, destination.toString());
});

app.post("/token", (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier, refresh_token, resource } = req.body || {};

  if (grant_type === "authorization_code") {
    const record = AUTH_CODES.get(code);
    AUTH_CODES.delete(code);
    const client = readClientId(client_id);
    if (!record || !client || record.expires_at < Date.now() ||
        record.client_id !== client_id || record.redirect_uri !== redirect_uri ||
        !client.redirect_uris.includes(redirect_uri) ||
        record.resource !== (resource || RESOURCE) ||
        typeof code_verifier !== "string" ||
        !safeEqual(sha256Base64Url(code_verifier), record.code_challenge)) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    const now = Math.floor(Date.now() / 1000);
    const accessToken = signedToken({
      typ: "access", sub: "server-owner", aud: RESOURCE,
      client_id, scope: "github", iat: now, exp: now + 3600
    });
    const newRefreshToken = signedToken({
      typ: "refresh", sub: "server-owner", aud: RESOURCE,
      client_id, iat: now, exp: now + 60 * 60 * 24 * 90
    });
    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: newRefreshToken,
      scope: "github"
    });
  }

  if (grant_type === "refresh_token") {
    const payload = readSignedToken(refresh_token);
    const client = readClientId(client_id);
    if (!payload || payload.typ !== "refresh" ||
        payload.client_id !== client_id || !client ||
        (resource && resource !== RESOURCE)) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    const now = Math.floor(Date.now() / 1000);
    return res.json({
      access_token: signedToken({
        typ: "access", sub: "server-owner", aud: RESOURCE,
        client_id, scope: "github", iat: now, exp: now + 3600
      }),
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: signedToken({
        typ: "refresh", sub: "server-owner", aud: RESOURCE,
        client_id, iat: now, exp: now + 60 * 60 * 24 * 90
      }),
      scope: "github"
    });
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

// Health check
app.get("/", (_req, res) => res.send("GitHub Claude MCP is running"));
app.get("/health", (_req, res) => res.json({ ok: true }));

app.all("/mcp", async (req, res) => {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const payload = readSignedToken(token);

  if (!payload || payload.typ !== "access" || payload.aud !== RESOURCE) {
    res.set("WWW-Authenticate", 'Bearer resource_metadata="' + ISSUER + '/.well-known/oauth-protected-resource"');
    return res.status(401).json({ error: "invalid_token" });
  }
  if (req.method !== "POST") return res.status(405).send("Use POST");

  const mcp = createServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true
  });

  try {
    await mcp.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP error:", error);
    if (!res.headersSent) res.status(500).json({ error: "MCP request failed" });
  } finally {
    await transport.close();
    await mcp.close();
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("GitHub Claude MCP listening on port " + PORT);
});
