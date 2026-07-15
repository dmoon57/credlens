class GitlabClient {
  private token: string;

  constructor() {
    const token = process.env.GITLAB_PERSONAL_ACCESS_TOKEN;
    if (!token) {
      throw new Error(
        "GITLAB_PERSONAL_ACCESS_TOKEN environment variable is required to start the server"
      );
    }
    this.token = token;
  }

  isConfigured(): boolean {
    return this.token.length > 0;
  }
}

export default GitlabClient;
