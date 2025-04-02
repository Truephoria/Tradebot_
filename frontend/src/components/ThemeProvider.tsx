"use client";

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  ReactNode,
} from "react";

// Define the three possible themes
export type Theme = "light" | "dark" | "system";

interface ThemeContextType {
  theme: Theme;                 // Current theme state
  setTheme: (theme: Theme) => void; // Setter function to change theme
}

// Create a context so child components can read the current theme / setTheme
const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  // Default to "dark" (you can change this to "light" or "system")
  const [theme, setTheme] = useState<Theme>("dark");

  useEffect(() => {
    // This function removes existing classes and applies the new one
    const applyTheme = (currentTheme: Theme) => {
      const root = document.documentElement;
      // Remove both classes before adding one
      root.classList.remove("light", "dark");

      // Determine the actual theme if user picks "system"
      const effectiveTheme =
        currentTheme === "system"
          ? window.matchMedia("(prefers-color-scheme: dark)").matches
            ? "dark"
            : "light"
          : currentTheme;

      // Add the "light" or "dark" class to <html>
      root.classList.add(effectiveTheme);

      // Debug: see which theme was applied
      console.log("Applied theme:", effectiveTheme);
    };

    applyTheme(theme);

    // If user picks "system", we listen for system theme changes
    if (theme === "system") {
      const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
      // Handler triggers whenever OS switches to dark or light
      const handler = (e: MediaQueryListEvent) =>
        applyTheme(e.matches ? "dark" : "light");

      mediaQuery.addEventListener("change", handler);
      return () => {
        mediaQuery.removeEventListener("change", handler);
      };
    }
  }, [theme]);

  // Provide { theme, setTheme } to children
  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

// A convenience hook to read/use the theme context in child components
export function useTheme() {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
}