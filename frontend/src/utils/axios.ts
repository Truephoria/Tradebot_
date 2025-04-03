// frontend/src/utils/axios.ts
import axios from "axios";
import { useAuthStore } from "@/stores/auth-store";

const axiosInstance = axios.create({
  baseURL: "https://pkbk36mqmi.us-east-2.awsapprunner.com",
  timeout: 5000,
  withCredentials: true,
});

// Automatically add token to headers
axiosInstance.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-clear token and redirect on 401
axiosInstance.interceptors.response.use(
  (res) => res,
  (err) => {
    if (
      err?.response?.status === 401 &&
      typeof window !== 'undefined' &&
      !window.location.pathname.includes('/auth')
    ) {
      localStorage.removeItem('token');
      useAuthStore.getState().clearToken?.();
      window.location.href = '/auth';
    }
    return Promise.reject(err);
  }
);

export default axiosInstance;
