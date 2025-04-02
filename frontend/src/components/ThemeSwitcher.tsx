"use client";

import { useTheme } from "./ThemeProvider";
import { Button } from "./ui/button";
import { Sun, Moon, Laptop } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";

/**
 * A dropdown to choose between 'light', 'dark', or 'system' theme.
 * Depends on useTheme() from the ThemeProvider context.
 */
export function ThemeSwitcher() {
  const { theme, setTheme } = useTheme();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="icon" className="rounded-full">
          {/* Show icon based on current theme */}
          {theme === "light" ? (
            <Sun className="h-[1.2rem] w-[1.2rem]" />
          ) : theme === "dark" ? (
            <Moon className="h-[1.2rem] w-[1.2rem]" />
          ) : (
            <Laptop className="h-[1.2rem] w-[1.2rem]" />
          )}
          <span className="sr-only">Toggle theme</span>
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end">
        {/* LIGHT option */}
        <DropdownMenuItem
          onClick={() => setTheme("light")}
          // Optional highlight if current theme is "light"
          className={theme === "light" ? "bg-gray-100 dark:bg-gray-700" : ""}
        >
          <Sun className="mr-2 h-4 w-4" />
          <span>Light</span>
        </DropdownMenuItem>

        {/* DARK option */}
        <DropdownMenuItem
          onClick={() => setTheme("dark")}
          className={theme === "dark" ? "bg-gray-100 dark:bg-gray-700" : ""}
        >
          <Moon className="mr-2 h-4 w-4" />
          <span>Dark</span>
        </DropdownMenuItem>

        {/* SYSTEM option */}
        <DropdownMenuItem
          onClick={() => setTheme("system")}
          className={theme === "system" ? "bg-gray-100 dark:bg-gray-700" : ""}
        >
          <Laptop className="mr-2 h-4 w-4" />
          <span>System</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}