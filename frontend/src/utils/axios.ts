// frontend/src/utils/axios.ts
import axios from "axios";

const axiosServices = axios.create({
  baseURL: "http://localhost:5000",
  timeout: 5000, // 5-second timeout to prevent hanging
});

axiosServices.interceptors.response.use(
  (response) => response,
  (error) => {
    if (
      error.response?.status === 401 &&
      !window.location.href.includes("/auth")
    ) {
      window.location.pathname = "/auth";
    }
    return Promise.reject(
      (error.response && error.response.data) || "Wrong Services"
    );
  }
);

export default axiosServices;