// frontend/src/app/page.tsx
'use client'; // Required for client-side components/hooks
import Dashboard from '@/components/Dashboard';
import { AuthProvider } from '@/context/authProvider';

export default function Home() {
  return (
    <AuthProvider>
      <main className="min-h-[calc(100vh-73px)] animate-fade-in">
        <Dashboard />
      </main>
    </AuthProvider>
  );
}