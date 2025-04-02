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

  // Restore token on initial load
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    if (storedToken) {
      setToken(storedToken);
    }
  }, [setToken]);

  // Axios interceptors for request and response
  useEffect(() => {
    // Request interceptor to add token to headers
    const requestInterceptor = axios.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        const storedToken = localStorage.getItem('token');
        if (storedToken) {
          config.headers = config.headers || {};
          config.headers.Authorization = `Bearer ${storedToken}`;
        }
        return config;
      },
      (error: AxiosError) => {
        console.error('Axios request error:', error.message);
        return Promise.reject(error);
      }
    );

    // Response interceptor to log errors and handle 401
    const responseInterceptor = axios.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        console.error('Axios response error:', error.response?.data, error.message);
        if (
          error.response?.status === 401 &&
          !window.location.href.includes('/auth')
        ) {
          console.log('Redirecting to /auth due to 401 error');
          window.location.pathname = '/auth';
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.request.eject(requestInterceptor);
      axios.interceptors.response.eject(responseInterceptor);
    };
  }, []);

  // Check authentication status
  useEffect(() => {
    const checkAuth = async () => {
      if (typeof window === 'undefined') return;

      setIsCheckingAuth(true);
      const storedToken = localStorage.getItem('token');

      if (!storedToken) {
        if (pathname !== '/auth') {
          router.push(`/auth?from=${encodeURIComponent(pathname || '')}`);
        }
        setIsCheckingAuth(false);
        return;
      }

      try {
        const response = await axios.get('/api/@me');
        setUser(response.data.user as User);
        if (pathname === '/auth') {
          const from = new URLSearchParams(window.location.search).get('from') || '/';
          router.push(from);
        }
      } catch (err) {
        console.error('checkAuth error:', err);
        clearToken();
        localStorage.removeItem('token');
        setUser(null);
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
      setError(null);
      const response = await axios.post('/api/login', { email, password });
      const { token, user } = response.data;
      setToken(token);
      localStorage.setItem('token', token); // Save to localStorage
      setUser(user);

      const from = new URLSearchParams(window.location.search).get('from') || '/';
      router.push(from);
      return user;
    } catch (err: unknown) {
      const errorMessage = (err as AxiosError<{ error?: string }>).response?.data?.error || 'Login failed';
      console.error('Login error:', err); // Add logging for the full error
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  // Register
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
      localStorage.setItem('token', token); // Save to localStorage
      setUser(user);
      router.push('/');
      return user;
    } catch (err: unknown) {
      const errorMessage = (err as AxiosError<{ error?: string }>).response?.data?.error || 'Registration failed';
      console.error('Register error:', err); // Add logging for the full error
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  // Logout
  const logout = useCallback(() => {
    clearToken();
    localStorage.removeItem('token'); // Clear token from localStorage
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