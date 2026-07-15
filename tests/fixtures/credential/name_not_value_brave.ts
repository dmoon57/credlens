const BRAVE_API_KEY = process.env.BRAVE_API_KEY!;

if (!BRAVE_API_KEY) {
  console.error("Error: BRAVE_API_KEY environment variable is required");
  process.exit(1);
}

export function startServer(): void {
  console.log("Brave Search MCP server starting...");
}
