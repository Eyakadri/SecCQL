import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: '/', // Ensure the base path is set correctly
  plugins: [
    react({
      jsxRuntime: 'automatic',
      babel: {
        configFile: './.babelrc', // Explicitly use the .babelrc file
      },
    }),
  ],
  server: {
    port: 3001, // Frontend development server port
    strictPort: true,
    open: true, // Automatically open the browser
    proxy: {
      '/api': {
        target: 'http://localhost:5000', // Backend Flask server
        changeOrigin: true, // Adjust the origin of the host header to the target URL
        rewrite: (path) => path.replace(/^\/api/, ''), // Optional: Remove '/api' prefix if needed
      },
    },
  },
  build: {
    outDir: 'dist', // Output directory for the production build
  },
  resolve: {
    alias: {
      '@': '/src', // Alias for the src directory
    },
  },
});