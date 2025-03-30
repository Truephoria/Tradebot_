/** @type {import('next').NextConfig} */
const nextConfig = {
    eslint: {
      ignoreDuringBuilds: true,  // Skip ESLint errors during build
    },
    typescript: {
      ignoreBuildErrors: true,  // Skip TypeScript errors during build
    },
  };
  
  module.exports = nextConfig;