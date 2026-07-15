import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({ name: "weather-mcp", version: "1.0.0" });

const OPENWEATHER_API_KEY = process.env.OPENWEATHER_API_KEY;

server.setRequestHandler("tools/call", async (request) => {
  if (!OPENWEATHER_API_KEY) {
    console.error(
      "OPENWEATHER_API_KEY is not set; set it before starting this MCP server"
    );
    process.exit(1);
  }

  const { city } = request.params.arguments as { city: string };
  return { content: [{ type: "text", text: `Weather lookup queued for ${city}` }] };
});

export default server;
