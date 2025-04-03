'use client';

import { useState, useEffect, useCallback } from 'react';
import axios from '@/utils/axios';
import { AxiosError } from 'axios';
import { useRouter, usePathname } from 'next/navigation';
import { User } from '@/types/user';
import { useAuthStore } from '@/stores/auth-store';

export default function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const router = useRouter();
  const pathname = usePathname();
  const { token, setToken, clearToken } = useAuthStore();

  // Load token from localStorage on app start
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    if (storedToken) setToken(storedToken);
  }, [setToken]);

  // Axios interceptors
  useEffect(() => {
    const requestInterceptor = axios.interceptors.request.use(
      (config) => {
        const currentToken = localStorage.getItem('token');
        if (currentToken) {
          config.headers.Authorization = `Bearer ${currentToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    const responseInterceptor = axios.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (
          error.response?.status === 401 &&
          typeof window !== 'undefined' &&
          !window.location.pathname.includes('/auth')
        ) {
          clearToken();
          setUser(null);
          localStorage.removeItem('token');
          window.location.href = '/auth';
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.request.eject(requestInterceptor);
      axios.interceptors.response.eject(responseInterceptor);
    };
  }, [clearToken]);

  // Check auth on load or route change
  useEffect(() => {
    const checkAuth = async () => {
      if (typeof window === 'undefined') return;

      setIsCheckingAuth(true);
      const storedToken = localStorage.getItem('token');
      if (!storedToken) {
        clearToken();
        localStorage.removeItem('token');
        if (pathname !== '/auth') {
          router.push('/auth');
        }
        setIsCheckingAuth(false);
        return;
      }

      try {
        const res = await axios.get('/api/@me');
        setUser(res.data.user);

        // Only redirect from /auth if already logged in
        if (pathname === '/auth' && res.data.user) {
          const from = new URLSearchParams(window.location.search).get('from') || '/';
          router.push(from);
        }
      } catch (err) {
        console.error('Auth check failed:', err);
        clearToken();
        setUser(null);
        localStorage.removeItem('token');
        if (pathname !== '/auth') {
          router.push('/auth');
        }
      } finally {
        setIsCheckingAuth(false);
      }
    };

    checkAuth();
  }, [pathname, router, clearToken]);

  // Login
  const login = async (email: string, password: string): Promise<User> => {
    try {
      setLoading(true);
      const res = await axios.post('/api/login', { email, password });

      // 🧠 Store token in localStorage
      localStorage.setItem('token', res.data.token);
      setToken(res.data.token);
      setUser(res.data.user);

      const from = new URLSearchParams(window.location.search).get('from') || '/';
      router.push(from);
      return res.data.user;
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Login failed');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // Register
  const register = async (userData: { name: string; email: string; password: string }): Promise<User> => {
    try {
      setLoading(true);
      const res = await axios.post('/api/register', userData);

      // 🧠 Store token in localStorage
      localStorage.setItem('token', res.data.token);
      setToken(res.data.token);
      setUser(res.data.user);

      router.push('/');
      return res.data.user;
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Registration failed');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // Logout
  const logout = useCallback(() => {
    clearToken();
    localStorage.removeItem('token');
    setUser(null);
    router.push('/auth');
  }, [clearToken, router]);

  return {
    user,
    token,
    isAuthenticated: !!user && !!token,
    isCheckingAuth,
    loading,
    error,
    login,
    register,
    logout,
  };
}
