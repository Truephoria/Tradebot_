import axios from "axios";
import { useAuthStore } from "@/stores/auth-store";

const axiosInstance = axios.create({
  baseURL: "https://pkbk36mqmi.us-east-2.awsapprunner.com",
  timeout: 5000,
  withCredentials: true,
});

// REQUEST INTERCEPTOR
axiosInstance.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// RESPONSE INTERCEPTOR
axiosInstance.interceptors.response.use(
  (res) => res,
  async (err) => {
    const originalRequest = err.config;

    if (
      err.response?.status === 401 &&
      !originalRequest._retry &&
      typeof window !== 'undefined'
    ) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) {
        useAuthStore.getState().clearToken();
        window.location.replace('/auth'); // 👈 send to login instead of /auth
        return Promise.reject(err);
      }

      try {
        const res = await axios.post("https://pkbk36mqmi.us-east-2.awsapprunner.com/api/refresh", {
          refreshToken
        });

        const newToken = res.data.token;
        useAuthStore.getState().setToken(newToken, refreshToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;

        return axiosInstance(originalRequest);
      } catch (refreshError) {
        useAuthStore.getState().clearToken();
        window.location.replace('/auth'); // 👈 send to login instead of /auth
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(err);
  }
);

export default axiosInstance;
