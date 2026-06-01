import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

interface AuthState {
  token: string;
  setToken: (token: string) => void;
}

const AuthContext = createContext<AuthState>({
  token: '',
  setToken: () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState(() => localStorage.getItem('smgglrs_token') || '');

  const setToken = useCallback((t: string) => {
    localStorage.setItem('smgglrs_token', t);
    setTokenState(t);
  }, []);

  return (
    <AuthContext.Provider value={{ token, setToken }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
