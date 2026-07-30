export async function mutateApi(
  path: string,
  method: string,
  body?: unknown,
  token?: string,
): Promise<Response> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
}
