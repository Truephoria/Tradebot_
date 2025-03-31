import React from 'react';
import Navbar from '@/components/Navbar';
import Dashboard from '@/components/Dashboard';

const Index = () => {
  return (
    <div className="min-h-screen bg-background transition-colors duration-300">
      <Navbar />
      <main className="min-h-[calc(100vh-73px)] animate-fade-in">
        <Dashboard />
      </main>
    </div>
  );
};

export default Index;