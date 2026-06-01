import { useAuth } from '../contexts/AuthContext';
import { useCallback } from 'react';

export function useApi() {
  const { token } = useAuth();

  const fetchApi = useCallback(async (path: string, init?: RequestInit): Promise<Response> => {
    const headers: Record<string, string> = {
      ...(init?.headers as Record<string, string> || {}),
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return fetch(path, { ...init, headers });
  }, [token]);

  return { fetchApi };
}

export async function fetchJson<T>(path: string, token?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const resp = await fetch(path, { headers });
  if (!resp.ok) {
    throw new Error(`API error: ${resp.status} ${resp.statusText}`);
  }
  return resp.json();
}
