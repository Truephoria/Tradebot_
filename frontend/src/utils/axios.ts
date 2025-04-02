// frontend/src/utils/axios.ts
import axios from "axios";

const axiosServices = axios.create({
  baseURL: "https://pkbk36mqmi.us-east-2.awsapprunner.com",
  timeout: 5000,
  withCredentials: true, // ⬅️ Needed for cookies/sessions with Flask
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