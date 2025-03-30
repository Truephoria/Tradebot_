// frontend/src/pages/404.tsx
'use client'; // Required for client-side hooks in Next.js
import { useEffect } from 'react';
import { usePathname } from 'next/navigation'; // Replace react-router-dom with Next.js navigation
import { Button } from '@/components/ui/button';

const NotFound = () => {
  const pathname = usePathname(); // Get the current URL path

  useEffect(() => {
    console.error('404 Error: User attempted to access non-existent route:', pathname);
  }, [pathname]);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-slate-50 px-4">
      <div className="text-center max-w-md animate-fade-in">
        <div className="w-20 h-20 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-6">
          <span className="text-4xl font-light text-slate-400">404</span>
        </div>
        <h1 className="text-3xl font-semibold text-slate-900 mb-2">Page not found</h1>
        <p className="text-slate-500 mb-8">
          We couldn't find the page you're looking for. Please check the URL or return to the dashboard.
        </p>
        <Button asChild className="px-8">
          <a href="/">Return to Dashboard</a>
        </Button>
      </div>
    </div>
  );
};

export default NotFound;
