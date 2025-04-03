'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useAuthStore } from '@/stores/auth-store';

interface WithAuthOptions {
  redirectTo?: string; // Default redirect path if not authenticated
}

export default function withAuth<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  { redirectTo = '/auth' }: WithAuthOptions = {}
) {
  return function WithAuthComponent(props: P) {
    const { token } = useAuthStore();
    const router = useRouter();
    const [isAuthChecked, setIsAuthChecked] = useState(false);

    // 1. Set hydration complete after Zustand has had time to read from localStorage
    useEffect(() => {
      setIsAuthChecked(true);
    }, []);

    // 2. Redirect to login if no token
    const handleRedirect = useCallback(() => {
      if (isAuthChecked && !token) {
        router.push(redirectTo);
      }
    }, [isAuthChecked, token, router, redirectTo]);

    useEffect(() => {
      handleRedirect();
    }, [handleRedirect]);

    // 3. Wait for hydration before rendering anything
    if (!isAuthChecked) {
      return <div>Loading...</div>;
    }

    // 4. Authenticated users see the wrapped component
    return <WrappedComponent {...props} />;
  };
}
