
import express from "express";
import { timingSafeEqual } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = Number(process.env.PORT || 3000);
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;

if (!GITHUB_TOKEN || !MCP_AUTH_TOKEN) {
  throw new Error(
    "Missing GITHUB_TOKEN or MCP_AUTH_TOKEN environment variable"
  );
}

function isAuthorized(req) {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  const supplied = Buffer.from(token);
  const expected = Buffer.from(MCP_AUTH_TOKEN);

  return (
    supplied.length === expected.length &&
    timingSafeEqual(supplied, expected)
  );
}

async function github(path, options = {}) {
  const response = await fetch(
    `https://api.github.com${path}`,
    {
      ...options,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        "X-GitHub-Api-Version": "2022-11-28",
        ...(options.body
          ? { "Content-Type": "application/json" }
          : {}),
        ...options.headers
      }
    }
  );

  const text = await response.text();

  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { message: text };
  }

  if (!response.ok) {
    throw new Error(
      `GitHub API ${response.status}: ${data.message || text}`
    );
  }

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

// Health check
app.get("/", (_req, res) => {
  res.send("GitHub Claude MCP is running");
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// MCP endpoint
app.all("/mcp", async (req, res) => {
  if (!isAuthorized(req)) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  if (req.method !== "POST") {
    return res.status(405).send("Use POST");
  }

  const mcp = createServer();

  const transport =
    new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });

  try {
    await mcp.connect(transport);
    await transport.handleRequest(
      req,
      res,
      req.body
    );
  } catch (error) {
    console.error("MCP error:", error);

    if (!res.headersSent) {
      res.status(500).json({
        error: "MCP request failed"
      });
    }
  } finally {
    await transport.close();
    await mcp.close();
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `GitHub Claude MCP listening on port ${PORT}`
  );
});
        
