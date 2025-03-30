// frontend/src/pages/dashboard.tsx
import Dashboard from '@/components/Dashboard';
import { AuthProvider } from '@/context/authProvider';

export default function DashboardPage() {
  return (
    <AuthProvider>
      <Dashboard />
    </AuthProvider>
  );
}