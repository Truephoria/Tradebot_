// frontend/src/hooks/useAuth.tsx
'use client';
import { useState, useEffect, useCallback } from 'react';
import axios from '@/utils/axios';
import { AxiosError } from 'axios';
import { useRouter, usePathname } from 'next/navigation';
import { User } from '@/types/user';
import type { InternalAxiosRequestConfig } from 'axios';
import { useAuthStore } from '@/stores/auth-store';

export default function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [isCheckingAuth, setIsCheckingAuth] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();
  const pathname = usePathname();
  const { token, setToken, clearToken } = useAuthStore();

  // Request interceptor for token
  useEffect(() => {
    const interceptor = axios.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        if (token) {
          config.headers = config.headers || {};
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error: AxiosError) => Promise.reject(error)
    );
    return () => axios.interceptors.request.eject(interceptor);
  }, [token]);

  // Check authentication status
  useEffect(() => {
    const checkAuth = async () => {
      if (typeof window === 'undefined') return; // Skip on server
      console.log('checkAuth: token=', token, 'pathname=', pathname);

      setIsCheckingAuth(true);

      // If no token and not on /auth, redirect to /auth
      if (!token) {
        if (pathname !== '/auth') {
          router.push(`/auth?from=${encodeURIComponent(pathname || '')}`);
        }
        setIsCheckingAuth(false);
        return;
      }

      // If token exists, verify it
      try {
        const response = await axios.get('/api/@me');
        setUser(response.data.user as User);
        if (pathname === '/auth') {
          const from = new URLSearchParams(window.location.search).get('from') || '/';
          router.push(from); // Redirect to intended page or home
        }
      } catch (err) {
        console.error('checkAuth error:', err);
        clearToken(); // Clear invalid token
        setUser(null);
        if (pathname !== '/auth') {
          router.push('/auth');
        }
      } finally {
        setIsCheckingAuth(false);
      }
    };

    checkAuth();
  }, [pathname, token, router, clearToken]);

  const login = async (email: string, password: string): Promise<User> => {
    try {
      setLoading(true);
      setError(null);
      console.log('Attempting login with:', { email, password });
      const response = await axios.post('/api/login', { email, password });
      console.log('Login response:', response.data);

      const { token, user } = response.data;
      setToken(token);
      setUser(user);

      const from = new URLSearchParams(window.location.search).get('from') || '/';
      router.push(from);

      return user;
    } catch (err: unknown) {
      const errorMessage = (err as AxiosError<{ error?: string }>).response?.data?.error || 'Login failed';
      console.error('Login error:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const register = async (userData: {
    name: string;
    email: string;
    password: string;
  }): Promise<User> => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.post('/api/register', userData);
      const { token, user } = response.data;
      setToken(token);
      setUser(user);
      router.push('/');
      return user;
    } catch (err: unknown) {
      const errorMessage = (err as AxiosError<{ error?: string }>).response?.data?.error || 'Registration failed';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
    router.push('/auth');
  }, [clearToken, router]);

  return {
    user,
    token,
    isCheckingAuth,
    loading,
    error,
    login,
    register,
    logout,
    isAuthenticated: !!token,
  };
}