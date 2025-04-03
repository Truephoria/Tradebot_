// frontend/src/stores/auth-store.ts
import { create } from 'zustand';

interface AuthState {
  token: string | null;
  refreshToken: string | null;
  setToken: (token: string | null, refreshToken?: string | null) => void;
  clearToken: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: typeof window !== 'undefined' ? localStorage.getItem('token') : null,
  refreshToken: typeof window !== 'undefined' ? localStorage.getItem('refreshToken') : null,
  setToken: (token, refreshToken) => {
    if (typeof window !== 'undefined') {
      if (token) localStorage.setItem('token', token);
      if (refreshToken) localStorage.setItem('refreshToken', refreshToken);
    }
    set({ token, refreshToken });
  },
  clearToken: () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
    }
    set({ token: null, refreshToken: null });
  },
}));
