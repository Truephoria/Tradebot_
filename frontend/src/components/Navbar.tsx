// frontend/src/components/Navbar.tsx
'use client';
import { usePathname } from 'next/navigation';
import React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { cn } from '@/lib/utils';
import { ThemeSwitcher } from './ThemeSwitcher';
import { LogOut } from 'lucide-react';
import { toast } from 'sonner';
import useAuth from '@/hooks/useAuth'; // Import useAuth

interface NavbarProps {
  className?: string;
}

const Navbar: React.FC<NavbarProps> = ({ className }) => {
  const router = useRouter();
  const currentPath = usePathname();
  const { user, logout, isAuthenticated } = useAuth(); // Use auth hook

  // Handle sign out
  const handleSignOut = () => {
    logout(); // Use the logout function from useAuth
    toast.success('Signed out successfully');
  };

  return (
    <header
      className={cn(
        'w-full py-3 px-6 bg-card/80 backdrop-blur-md border-b border-border sticky top-0 z-50 transition-all duration-300 ease-in-out',
        className
      )}
    >
      <div className="container mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className="h-9 w-9 rounded-lg bg-primary/90 flex items-center justify-center transition-transform hover:scale-105">
            <svg
              viewBox="0 0 24 24"
              width="20"
              height="20"
              stroke="currentColor"
              strokeWidth="2"
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="text-white"
            >
              <path d="M12 2L2 7l10 5 10-5-10-5z" />
              <path d="M2 17l10 5 10-5" />
              <path d="M2 12l10 5 10-5" />
            </svg>
          </div>
          <Link
            href="/"
            className="text-xl font-semibold text-foreground hover:text-primary transition-colors"
          >
            Signal Sentry
          </Link>
        </div>

        <nav className="hidden md:flex items-center space-x-1 border border-input rounded-lg p-1">
          <NavItem href="/" active={currentPath === '/'}>
            Dashboard
          </NavItem>
          <NavItem href="/settings" active={currentPath === '/settings'}>
            Settings
          </NavItem>
        </nav>

        <div className="flex items-center space-x-4">
          <ThemeSwitcher />

          <div className="flex items-center space-x-2">
            {isAuthenticated && (
              <button
                onClick={handleSignOut}
                className="p-2 rounded-md hover:bg-secondary flex items-center justify-center text-muted-foreground hover:text-foreground transition-colors"
                title="Sign out"
              >
                <LogOut size={18} />
              </button>
            )}

            <div className="relative w-10 h-10 rounded-full bg-secondary flex items-center justify-center ring-2 ring-white overflow-hidden hover:ring-primary/30 transition-all cursor-pointer dark:ring-slate-800">
              <span className="text-sm font-medium text-primary">
                {user
                  ? user.name?.substring(0, 2).toUpperCase() ||
                    user.email?.substring(0, 2).toUpperCase()
                  : 'AS'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

interface NavItemProps {
  children: React.ReactNode;
  active?: boolean;
  href: string;
}

const NavItem: React.FC<NavItemProps> = ({ children, active, href }) => {
  return (
    <Link
      href={href}
      className={cn(
        'relative px-3 py-2 text-sm font-medium rounded-md transition-all',
        active
          ? 'text-primary bg-primary/10'
          : 'text-muted-foreground hover:text-foreground hover:bg-accent'
      )}
    >
      {children}
      {active && (
        <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary rounded-full transform" />
      )}
    </Link>
  );
};

export default Navbar;