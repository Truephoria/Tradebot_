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

  // Initial token load
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

  // Auth check on load
  useEffect(() => {
    const checkAuth = async () => {
      if (typeof window === 'undefined') return;

      setIsCheckingAuth(true);
      const storedToken = localStorage.getItem('token');
      if (!storedToken) {
        clearToken();
        localStorage.removeItem('token');
        if (pathname !== '/auth') {
          router.push('/login');
        }
        setIsCheckingAuth(false);
        return;
      }

      try {
        const res = await axios.get('/api/@me');
        setUser(res.data.user);
        if (pathname === '/auth') {
          const from = new URLSearchParams(window.location.search).get('from') || '/';
          router.push(from);
        }
      } catch (err) {
        console.error('Auth check failed:', err);
        clearToken();
        setUser(null);
        router.push('/login');
      } finally {
        setIsCheckingAuth(false);
      }
    };

    checkAuth();
  }, [pathname, router, clearToken]);

  const login = async (email: string, password: string): Promise<User> => {
    try {
      setLoading(true);
      const res = await axios.post('/api/login', { email, password });
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

  const register = async (userData: { name: string; email: string; password: string; }): Promise<User> => {
    try {
      setLoading(true);
      const res = await axios.post('/api/register', userData);
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

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
    router.push('/login');
  }, [clearToken, router]);

  return {
    user,
    token,
    isAuthenticated: !!token,
    isCheckingAuth,
    loading,
    error,
    login,
    register,
    logout,
  };
}
