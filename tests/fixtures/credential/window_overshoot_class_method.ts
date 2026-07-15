class SlackClient {
  private getBotToken(): string {
    const botToken = process.env.SLACK_BOT_TOKEN;
    if (!botToken) {
      console.error("SLACK_BOT_TOKEN environment variable is missing");
      process.exit(1);
    }
    return botToken;
  }

  isReady(): boolean {
    return this.getBotToken().length > 0;
  }
}

export default SlackClient;
