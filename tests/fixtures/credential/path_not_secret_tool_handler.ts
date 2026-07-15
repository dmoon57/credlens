import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import fs from "fs";

const server = new Server({ name: "sqlite-mcp", version: "1.0.0" });

const DB_FILE_PATH = process.env.SQLITE_DB_FILE_PATH || "./data/app.db";

server.setRequestHandler("tools/call", async (request) => {
  const { query } = request.params.arguments as { query: string };
  const exists = fs.existsSync(DB_FILE_PATH);
  console.log(`Running query against database file: ${DB_FILE_PATH} (exists=${exists})`);
  return { content: [{ type: "text", text: `executed: ${query}` }] };
});

export default server;
