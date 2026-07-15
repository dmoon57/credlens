import fs from "fs";

const credentialsPath =
  process.env.GDRIVE_CREDENTIALS_PATH || "./.gdrive-credentials.json";

export function saveCredentials(auth: { credentials: unknown }): void {
  fs.writeFileSync(credentialsPath, JSON.stringify(auth.credentials));
  console.log("Credentials saved. You can now run the server.");
}

export function credentialsLocation(): string {
  console.log(`Reading credentials from ${credentialsPath}`);
  return credentialsPath;
}
