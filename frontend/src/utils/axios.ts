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
      typeof window !== 'undefined' &&
      err?.response?.status === 401
    ) {
      const pathname = window.location.pathname;
      if (!pathname.startsWith('/auth')) {
        useAuthStore.getState().clearToken();
        localStorage.removeItem('token');
        window.location.replace('/auth'); // soft reload
      }
    }
    return Promise.reject(err);
  }
);

export default axiosInstance;
