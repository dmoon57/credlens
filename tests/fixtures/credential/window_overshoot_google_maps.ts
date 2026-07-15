function getApiKey(): string {
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;
  if (!apiKey) {
    console.error("GOOGLE_MAPS_API_KEY environment variable is not set");
    process.exit(1);
  }
  return apiKey;
}

export function isMapsConfigured(): boolean {
  return getApiKey().length > 0;
}
