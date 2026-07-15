class NotionClient {
  private secret: string;

  constructor() {
    const apiKey = process.env.NOTION_API_KEY;
    this.secret = apiKey;
  }

  async queryDatabase(databaseId: string): Promise<unknown> {
    const authHeader = this.secret;
    const url = `https://api.notion.com/v1/databases/${databaseId}/query`;
    const response = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${authHeader}` } });
    return response.json();
  }
}

export default NotionClient;
