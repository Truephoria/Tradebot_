'use client'; // Required for client-side components/hooks
import Dashboard from '@/components/Dashboard';
import Navbar from '@/components/Navbar';
import { AuthProvider } from '@/context/authProvider';

export default function DashboardPage() {
  return (
    <AuthProvider>
      <div className="min-h-screen bg-background transition-colors duration-300">
        <Navbar />
        <main className="min-h-[calc(100vh-73px)] animate-fade-in">
          <Dashboard />
        </main>
      </div>
    </AuthProvider>
  );
}