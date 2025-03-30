"use client"; // Required for client-side hooks/context in Next.js App Router
import { createContext, useContext, ReactNode } from "react";
import useAuth from "../hooks/useAuth"; // Assuming this is in src/hooks/useAuth.tsx
import { User } from "@/types/user"; // Ensure this path matches your project
import { AxiosInstance } from "axios";
import axiosServices from "@/utils/axios"; // Import your axios instance

// Define the shape of the auth context
type AuthContextType = {
  user: User | null;
  token: string | null;
  loading: boolean;
  error: any; // Consider typing this more specifically (e.g., Error | null)
  login: (email: string, password: string) => Promise<User>;
  register: (userData: {
    name: string;
    email: string;
    password: string;
  }) => Promise<User>;
  logout: () => void;
  authAxios: AxiosInstance; // Always an AxiosInstance
  isAuthenticated: boolean;
};

// Create the context with a default value
const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  loading: true,
  error: null,
  login: async () => {
    throw new Error("login function must be used within AuthProvider");
  },
  register: async () => {
    throw new Error("register function must be used within AuthProvider");
  },
  logout: () => {
    throw new Error("logout function must be used within AuthProvider");
  },
  authAxios: axiosServices, // Use the imported axios instance
  isAuthenticated: false,
});

// AuthProvider component with typed children prop
interface AuthProviderProps {
  children: ReactNode; // Explicitly type children
}

export function AuthProvider({ children }: AuthProviderProps) {
  const auth = useAuth();

  // Extend the auth object with authAxios
  const authValue: AuthContextType = {
    ...auth,
    authAxios: axiosServices, // Add the axios instance here
  };

  return <AuthContext.Provider value={authValue}>{children}</AuthContext.Provider>;
}

// Custom hook to use the auth context
export function useAuthContext() {
  const context = useContext(AuthContext);

  if (context === undefined) {
    throw new Error("useAuthContext must be used within an AuthProvider");
  }

  return context;
}