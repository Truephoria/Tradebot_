/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  reactStrictMode: true, // Keep this for better error reporting
  typescript: {
    ignoreBuildErrors: true, // Skips TypeScript type checking during build
  },
  eslint: {
    ignoreDuringBuilds: true, // Skips ESLint linting during build
  },
};

module.exports = nextConfig;


// next.config.js
