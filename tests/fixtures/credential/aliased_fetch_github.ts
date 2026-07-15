const token = process.env.GITHUB_TOKEN;
const auth = token;

export async function listRepos(user: string): Promise<unknown> {
  const response = await fetch(`https://api.example.com/users/${user}/repos?t=${auth}`);
  return response.json();
}
